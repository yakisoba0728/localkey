//! `authenticatorCredentialManagement` (CTAP 2.1 §6.8, command 0x0A) and its FIDO_2_1_PRE
//! prototype `credentialMgmtPreview` (command 0x41, same parameters and behaviour).
//!
//! - Every subcommand except the two "get next" ones needs a pinUvAuthToken with the `cm`
//!   permission. The checks run in the order of §6.8.2 to §6.8.6: pinUvAuthParam absent
//!   `CTAP2_ERR_PUAT_REQUIRED`; a mandatory parameter absent (pinUvAuthProtocol, or a
//!   required subCommandParams member) `CTAP2_ERR_MISSING_PARAMETER`; pinUvAuthProtocol
//!   unsupported `CTAP1_ERR_INVALID_PARAMETER`; `verify(pinUvAuthToken, uint8(subCommand) ||
//!   subCommandParams, pinUvAuthParam)` and the `cm` permission `CTAP2_ERR_PIN_AUTH_INVALID`.
//!   `subCommandParams` is MACed as received.
//! - RP-scoped tokens (a permissions RP ID, §6.5.5.7) cannot read metadata or enumerate
//!   RPs, and reach only credentials of their RP (§6.8.2, §6.8.3, §6.8.4, §6.8.5, §6.8.6).
//! - Model policy for the prototype command: a token from the superseded getPinToken
//!   (§6.5.5.4, permissions mc and ga only) is accepted on 0x41, because FIDO_2_1_PRE
//!   platforms, the only users of 0x41, know no other way to get a token. 0x0A stays strict.
//! - The enumeration state (§6.8.3, §6.8.4) is discarded by any other command or
//!   subcommand, and when the pinUvAuthToken that authenticated the "begin" subcommand
//!   expires (§6: "An authenticator MUST discard the state for a stateful command if the
//!   pinUvAuthToken that authenticated the state initializing command expires").
//! - deleteCredential and updateUserInformation of a credential that is not stored are
//!   `CTAP2_ERR_NO_CREDENTIALS` (`reference/BEHAVIOR_CATALOG.md` FIDO: "Credential
//!   management delete/update of a missing resident credential returns
//!   CTAP2_ERR_NO_CREDENTIALS (0x2e)"), as are enumerations that find nothing.

use lk_codec::cbor::{MapBuilder, Value};
use lk_core::Host;
use lk_crypto::sha256;

use crate::client_pin::{permission, supported_protocol};
use crate::credential::CredSecret;
use crate::get_info::DISCOVERABLE_CAPACITY;
use crate::make_credential::{MAX_STORED_NAME, truncate};
use crate::pin_protocol::PinProtocol;
use crate::request::{
    CtapResult, PUBLIC_KEY, Params, bytes, map, required, text, text_key, uint_key, unsigned,
};
use crate::state::Resident;
use crate::{Authenticator, ok, status};

/// credentialManagement subcommands (§6.8 table).
pub(crate) mod subcommand {
    pub const GET_CREDS_METADATA: u64 = 0x01;
    pub const ENUMERATE_RPS_BEGIN: u64 = 0x02;
    pub const ENUMERATE_RPS_GET_NEXT_RP: u64 = 0x03;
    pub const ENUMERATE_CREDENTIALS_BEGIN: u64 = 0x04;
    pub const ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL: u64 = 0x05;
    pub const DELETE_CREDENTIAL: u64 = 0x06;
    pub const UPDATE_USER_INFORMATION: u64 = 0x07;
}

/// What enumerateRPsGetNextRP / enumerateCredentialsGetNextCredential continue, and the
/// serial of the pinUvAuthToken that authenticated the "begin" subcommand: the state ends
/// when that token expires (CTAP 2.1 §6, stateful commands).
#[derive(Debug)]
pub(crate) enum Enumeration {
    Rps {
        rp_ids: Vec<String>,
        next: usize,
        token: u64,
    },
    Credentials {
        ids: Vec<Vec<u8>>,
        next: usize,
        token: u64,
    },
}

impl Enumeration {
    fn token(&self) -> u64 {
        match self {
            Enumeration::Rps { token, .. } | Enumeration::Credentials { token, .. } => *token,
        }
    }
}

/// The `user` member of subCommandParams: a PublicKeyCredentialUserEntity (WebAuthn L2
/// §5.4.3) with its members still optional.
#[derive(Debug)]
struct UserParam {
    id: Option<Vec<u8>>,
    name: Option<String>,
    display_name: Option<String>,
}

/// subCommandParams (§6.8 table), type-checked.
#[derive(Debug, Default)]
struct SubParams {
    rp_id_hash: Option<Vec<u8>>,
    /// credentialID: a PublicKeyCredentialDescriptor `(type, id)`, members optional here.
    credential: Option<(Option<String>, Option<Vec<u8>>)>,
    user: Option<UserParam>,
}

impl SubParams {
    fn parse(value: Option<&Value>) -> CtapResult<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let entries = map(value)?;
        let rp_id_hash = uint_key(entries, 0x01)
            .map(bytes)
            .transpose()?
            .map(<[u8]>::to_vec);
        let credential = uint_key(entries, 0x02)
            .map(|v| -> CtapResult<_> {
                let d = map(v)?;
                let kind = text_key(d, "type")
                    .map(text)
                    .transpose()?
                    .map(str::to_owned);
                let id = text_key(d, "id")
                    .map(bytes)
                    .transpose()?
                    .map(<[u8]>::to_vec);
                Ok((kind, id))
            })
            .transpose()?;
        let user = uint_key(entries, 0x03)
            .map(|v| -> CtapResult<_> {
                let u = map(v)?;
                let id = text_key(u, "id")
                    .map(bytes)
                    .transpose()?
                    .map(<[u8]>::to_vec);
                let name = text_key(u, "name")
                    .map(text)
                    .transpose()?
                    .map(str::to_owned);
                let display_name = text_key(u, "displayName")
                    .map(text)
                    .transpose()?
                    .map(str::to_owned);
                Ok(UserParam {
                    id,
                    name,
                    display_name,
                })
            })
            .transpose()?;
        Ok(Self {
            rp_id_hash,
            credential,
            user,
        })
    }

    /// The credentialID's id; `CTAP2_ERR_MISSING_PARAMETER` without it. A descriptor of
    /// another type names no credential of this authenticator (`None`).
    fn credential_id(&self) -> CtapResult<Option<&[u8]>> {
        let (kind, id) = self.credential.as_ref().ok_or(status::MISSING_PARAMETER)?;
        let kind = kind.as_deref().ok_or(status::MISSING_PARAMETER)?;
        let id = id.as_deref().ok_or(status::MISSING_PARAMETER)?;
        Ok((kind == PUBLIC_KEY).then_some(id))
    }
}

/// An RP entity with the stored RP ID (§6.8.3 response `rp`; the RP name is not stored).
fn rp_entity(rp_id: &str) -> Value {
    MapBuilder::new().insert("id", rp_id).build()
}

impl Authenticator {
    pub(crate) fn credential_management(
        &mut self,
        params: &[u8],
        preview: bool,
        host: &mut dyn Host,
    ) -> Vec<u8> {
        // Any subcommand other than the matching "get next" discards the enumeration, and
        // so does the expiry of the token that began it (§6 "MUST discard the state").
        let now = host.now();
        let enumeration = self
            .cred_mgmt
            .take()
            .filter(|e| self.pin.token_still_valid(e.token(), now));
        match self.credential_management_inner(params, preview, enumeration, host) {
            Ok(response) => response,
            Err(code) => vec![code],
        }
    }

    fn credential_management_inner(
        &mut self,
        params: &[u8],
        preview: bool,
        enumeration: Option<Enumeration>,
        host: &mut dyn Host,
    ) -> CtapResult<Vec<u8>> {
        let p = Params::decode(params)?;
        let sub = p.get(0x01).map(unsigned).transpose()?;
        let sub_params = SubParams::parse(p.get(0x02))?;
        let protocol = p.get(0x03).map(unsigned).transpose()?;
        let param = p.get(0x04).map(bytes).transpose()?;
        let sub = required(sub)?;
        let auth = Auth {
            sub,
            raw_params: p.raw(0x02),
            protocol,
            param,
            preview,
        };
        match sub {
            subcommand::GET_CREDS_METADATA => {
                let protocol = auth.protocol()?.supported()?;
                if self.cm_verify(&auth, protocol, host)?.is_some() {
                    return Err(status::PIN_AUTH_INVALID);
                }
                let count = self.state.residents.len();
                Ok(ok(MapBuilder::new()
                    .insert(0x01, count)
                    .insert(0x02, DISCOVERABLE_CAPACITY.saturating_sub(count))
                    .build()))
            }
            subcommand::ENUMERATE_RPS_BEGIN => {
                let protocol = auth.protocol()?.supported()?;
                if self.cm_verify(&auth, protocol, host)?.is_some() {
                    return Err(status::PIN_AUTH_INVALID);
                }
                let mut rp_ids: Vec<String> = Vec::new();
                for r in &self.state.residents {
                    if !rp_ids.contains(&r.rp_id) {
                        rp_ids.push(r.rp_id.clone());
                    }
                }
                let first = rp_ids.first().ok_or(status::NO_CREDENTIALS)?;
                let response = ok(MapBuilder::new()
                    .insert(0x03, rp_entity(first))
                    .insert(0x04, sha256(first.as_bytes()).to_vec())
                    .insert(0x05, rp_ids.len())
                    .build());
                if rp_ids.len() > 1 {
                    let token = self.pin.token_serial().ok_or(status::OTHER)?;
                    self.cred_mgmt = Some(Enumeration::Rps {
                        rp_ids,
                        next: 1,
                        token,
                    });
                }
                Ok(response)
            }
            subcommand::ENUMERATE_RPS_GET_NEXT_RP => match enumeration {
                Some(Enumeration::Rps {
                    rp_ids,
                    next,
                    token,
                }) => {
                    let rp = rp_ids.get(next).ok_or(status::NOT_ALLOWED)?;
                    let response = ok(MapBuilder::new()
                        .insert(0x03, rp_entity(rp))
                        .insert(0x04, sha256(rp.as_bytes()).to_vec())
                        .build());
                    if next + 1 < rp_ids.len() {
                        self.cred_mgmt = Some(Enumeration::Rps {
                            rp_ids,
                            next: next + 1,
                            token,
                        });
                    }
                    Ok(response)
                }
                _ => Err(status::NOT_ALLOWED),
            },
            subcommand::ENUMERATE_CREDENTIALS_BEGIN => {
                let protocol = auth.protocol()?;
                let rp_id_hash = sub_params
                    .rp_id_hash
                    .clone()
                    .ok_or(status::MISSING_PARAMETER)?;
                let protocol = protocol.supported()?;
                let bound = self.cm_verify(&auth, protocol, host)?;
                if bound.is_some_and(|rp| sha256(rp.as_bytes()).as_slice() != rp_id_hash) {
                    return Err(status::PIN_AUTH_INVALID);
                }
                let ids: Vec<Vec<u8>> = self
                    .state
                    .residents
                    .iter()
                    .filter(|r| r.rp_id_hash.as_slice() == rp_id_hash)
                    .map(|r| r.id.clone())
                    .collect();
                let first = ids.first().ok_or(status::NO_CREDENTIALS)?;
                let response = self.credential_response(first, Some(ids.len()))?;
                if ids.len() > 1 {
                    let token = self.pin.token_serial().ok_or(status::OTHER)?;
                    self.cred_mgmt = Some(Enumeration::Credentials {
                        ids,
                        next: 1,
                        token,
                    });
                }
                Ok(response)
            }
            subcommand::ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL => match enumeration {
                Some(Enumeration::Credentials { ids, next, token }) => {
                    let id = ids.get(next).ok_or(status::NOT_ALLOWED)?;
                    let response = self.credential_response(id, None)?;
                    if next + 1 < ids.len() {
                        self.cred_mgmt = Some(Enumeration::Credentials {
                            ids,
                            next: next + 1,
                            token,
                        });
                    }
                    Ok(response)
                }
                _ => Err(status::NOT_ALLOWED),
            },
            subcommand::DELETE_CREDENTIAL => {
                let protocol = auth.protocol()?;
                let id = sub_params.credential_id()?;
                let protocol = protocol.supported()?;
                let bound = self.cm_verify(&auth, protocol, host)?;
                let index = self.stored_credential(id, bound.as_deref())?;
                let mut next = self.state.clone();
                next.residents.remove(index);
                self.commit(next, host)?;
                Ok(vec![status::OK])
            }
            subcommand::UPDATE_USER_INFORMATION => {
                let protocol = auth.protocol()?;
                let id = sub_params.credential_id()?;
                let user = sub_params.user.as_ref().ok_or(status::MISSING_PARAMETER)?;
                let user_id = user.id.as_deref().ok_or(status::MISSING_PARAMETER)?;
                let protocol = protocol.supported()?;
                let bound = self.cm_verify(&auth, protocol, host)?;
                let index = self.stored_credential(id, bound.as_deref())?;
                let mut next = self.state.clone();
                let row = next.residents.get_mut(index).ok_or(status::OTHER)?;
                // §6.8.6: the user handle must match; names absent or empty are removed.
                if row.user_id != user_id {
                    return Err(status::INVALID_PARAMETER);
                }
                let keep = |name: &Option<String>| {
                    truncate(name.clone().filter(|n| !n.is_empty()), MAX_STORED_NAME)
                };
                row.user_name = keep(&user.name);
                row.display_name = keep(&user.display_name);
                self.commit(next, host)?;
                Ok(vec![status::OK])
            }
            _ => Err(status::INVALID_SUBCOMMAND),
        }
    }

    /// Verify the request's pinUvAuthParam and the `cm` permission; returns the token's
    /// permissions RP ID, if any.
    fn cm_verify(
        &mut self,
        auth: &Auth<'_>,
        protocol: (PinProtocol, &[u8]),
        host: &mut dyn Host,
    ) -> CtapResult<Option<String>> {
        let (protocol, param) = protocol;
        let sub = u8::try_from(auth.sub).map_err(|_| status::INVALID_SUBCOMMAND)?;
        let mut message = vec![sub];
        message.extend_from_slice(auth.raw_params.unwrap_or_default());
        let token = self.verified_token(protocol, &message, param, host.now())?;
        let allowed = token.permissions & permission::CM != 0 || (auth.preview && token.legacy);
        if !allowed {
            return Err(status::PIN_AUTH_INVALID);
        }
        Ok(token.rp_id.clone())
    }

    /// The index of the stored discoverable credential `id`; `CTAP2_ERR_NO_CREDENTIALS` if
    /// there is none, `CTAP2_ERR_PIN_AUTH_INVALID` if the token is bound to another RP.
    fn stored_credential(&self, id: Option<&[u8]>, bound: Option<&str>) -> CtapResult<usize> {
        let index = id
            .and_then(|id| self.state.residents.iter().position(|r| r.id == id))
            .ok_or(status::NO_CREDENTIALS)?;
        let row = self.state.residents.get(index).ok_or(status::OTHER)?;
        if bound.is_some_and(|rp| rp != row.rp_id) {
            return Err(status::PIN_AUTH_INVALID);
        }
        Ok(index)
    }

    /// One credential of an enumeration (§6.8.4 response): user, credentialID, publicKey,
    /// totalCredentials (first response only), credProtect and largeBlobKey.
    fn credential_response(&self, id: &[u8], total: Option<usize>) -> CtapResult<Vec<u8>> {
        let row: &Resident = self
            .state
            .residents
            .iter()
            .find(|r| r.id == id)
            .ok_or(status::NO_CREDENTIALS)?;
        let secret = self.state.secret.as_ref().ok_or(status::OTHER)?;
        let cred = CredSecret::unwrap(&row.id, secret, &row.rp_id_hash).ok_or(status::OTHER)?;
        let mut user = MapBuilder::new().insert("id", row.user_id.clone());
        if let Some(name) = &row.user_name {
            user.set("name", name.as_str());
        }
        if let Some(name) = &row.display_name {
            user.set("displayName", name.as_str());
        }
        let descriptor = MapBuilder::new()
            .insert("id", row.id.clone())
            .insert("type", PUBLIC_KEY)
            .build();
        let mut response = MapBuilder::new()
            .insert(0x06, user.build())
            .insert(0x07, descriptor)
            .insert(0x08, cred.cose_public_key())
            .insert(0x0A, row.cred_protect);
        if let Some(total) = total {
            response.set(0x09, total);
        }
        if let Some(key) = row.large_blob_key {
            response.set(0x0B, key.to_vec());
        }
        Ok(ok(response.build()))
    }
}

/// The authentication inputs of one request.
struct Auth<'a> {
    sub: u64,
    raw_params: Option<&'a [u8]>,
    protocol: Option<u64>,
    param: Option<&'a [u8]>,
    preview: bool,
}

impl<'a> Auth<'a> {
    /// pinUvAuthParam absent `CTAP2_ERR_PUAT_REQUIRED`; pinUvAuthProtocol absent
    /// `CTAP2_ERR_MISSING_PARAMETER`. Whether the protocol is supported is checked after
    /// the other mandatory parameters ([`Requested::supported`]).
    fn protocol(&self) -> CtapResult<Requested<'a>> {
        let param = self.param.ok_or(status::PUAT_REQUIRED)?;
        let protocol = required(self.protocol)?;
        Ok(Requested { protocol, param })
    }
}

/// A present pinUvAuthParam and pinUvAuthProtocol, the protocol not yet checked.
struct Requested<'a> {
    protocol: u64,
    param: &'a [u8],
}

impl<'a> Requested<'a> {
    /// pinUvAuthProtocol unsupported: `CTAP1_ERR_INVALID_PARAMETER`.
    fn supported(self) -> CtapResult<(PinProtocol, &'a [u8])> {
        Ok((supported_protocol(self.protocol)?, self.param))
    }
}

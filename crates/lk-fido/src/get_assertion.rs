//! `authenticatorGetAssertion` (CTAP 2.1 §6.2) and `authenticatorGetNextAssertion` (§6.3).

use lk_codec::cbor::{MapBuilder, Value};
use lk_core::{Host, Millis, Outcome};
use lk_crypto::{hmac_sha256, sha256};

use crate::client_pin::permission;
use crate::make_credential::{FLAG_ED, FLAG_UP, FLAG_UV};
use crate::pin_protocol::PinProtocol;
use crate::request::{
    CtapResult, PUBLIC_KEY, Params, boolean, bytes, descriptor_ids, map, options, required, text,
    uint_key, unsigned,
};
use crate::{Authenticator, Pending, ok, status};

/// getNextAssertion is refused this long after the previous assertion (CTAP 2.1 §6.3
/// step 3: "greater than 30 seconds").
pub(crate) const NEXT_ASSERTION_TIMEOUT_MS: Millis = 30_000;

/// hmac-secret input (CTAP 2.1 §12.5): `{1: keyAgreement, 2: saltEnc, 3: saltAuth,
/// 4?: pinUvAuthProtocol}`.
#[derive(Debug)]
pub(crate) struct HmacSecretInput {
    key_agreement: Vec<(Value, Value)>,
    salt_enc: Vec<u8>,
    salt_auth: Vec<u8>,
    protocol: Option<u64>,
}

fn hmac_secret_input(value: &Value) -> CtapResult<HmacSecretInput> {
    let entries = map(value)?;
    let get = |key: u64| uint_key(entries, key);
    Ok(HmacSecretInput {
        key_agreement: map(required(get(1))?)?.to_vec(),
        salt_enc: bytes(required(get(2))?)?.to_vec(),
        salt_auth: bytes(required(get(3))?)?.to_vec(),
        protocol: get(4).map(unsigned).transpose()?,
    })
}

/// Decrypted hmac-secret salts and the shared secret to encrypt the output with.
pub(crate) struct HmacSalts {
    protocol: PinProtocol,
    shared: Vec<u8>,
    /// salt1, or salt1 || salt2 (32 or 64 bytes).
    salts: Vec<u8>,
}

impl core::fmt::Debug for HmacSalts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HmacSalts")
            .field("protocol", &self.protocol)
            .field("salts", &(self.salts.len() / 32))
            .finish_non_exhaustive()
    }
}

/// Extension inputs of getAssertion (CTAP 2.1 §12).
#[derive(Debug, Default)]
struct Extensions {
    /// `"credBlob": true` (§12.2).
    cred_blob: bool,
    /// largeBlobKey input (§12.3).
    large_blob_key: Option<bool>,
    /// hmac-secret input (§12.5).
    hmac_secret: Option<HmacSecretInput>,
}

fn extensions(value: Option<&Value>) -> CtapResult<Extensions> {
    let mut ext = Extensions::default();
    let Some(value) = value else { return Ok(ext) };
    for (key, v) in map(value)? {
        match key.as_text() {
            Some("credBlob") => ext.cred_blob = boolean(v)?,
            Some("largeBlobKey") => ext.large_blob_key = Some(boolean(v)?),
            Some("hmac-secret") => ext.hmac_secret = Some(hmac_secret_input(v)?),
            _ => {}
        }
    }
    Ok(ext)
}

/// A validated getAssertion: the applicable credentials in the order they are served.
#[derive(Debug)]
pub(crate) struct Plan {
    client_data_hash: Vec<u8>,
    rp_id_hash: [u8; 32],
    uv: bool,
    /// Credential IDs: one for an allowList, newest first for discoverable credentials.
    ids: Vec<Vec<u8>>,
    /// Whether the credentials were found without an allowList (§6.2.2 step 12).
    discoverable: bool,
    ext: Extensions,
    /// hmac-secret salts, verified and decrypted before the touch (§12.5).
    hmac: Option<HmacSalts>,
    /// The pinUvAuthToken that authenticated the request, if any: the getNextAssertion
    /// state ends with it (CTAP 2.1 §6, stateful commands).
    token: Option<u64>,
}

/// The getNextAssertion state (CTAP 2.1 §6.3): the plan, the next credential to serve,
/// the UP flag of the original assertion and the time of the last assertion.
#[derive(Debug)]
pub(crate) struct NextAssertion {
    plan: Plan,
    next: usize,
    up: bool,
    last: Millis,
}

impl Authenticator {
    pub(crate) fn get_assertion(&mut self, params: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        match self.prepare_get_assertion(params, host) {
            Ok(outcome) => outcome,
            Err(code) => Outcome::Done(vec![code]),
        }
    }

    /// CTAP 2.1 §6.2.2 steps 1-10 up to the touch request (or the assertion itself when
    /// "up" is false).
    fn prepare_get_assertion(
        &mut self,
        params: &[u8],
        host: &mut dyn Host,
    ) -> CtapResult<Outcome<Vec<u8>>> {
        // §6.2.1 parameters.
        let p = Params::decode(params)?;
        let rp_id = text(required(p.get(0x01))?)?;
        let client_data_hash = bytes(required(p.get(0x02))?)?.to_vec();
        let allow_list = p.get(0x03).map(descriptor_ids).transpose()?;
        let ext = extensions(p.get(0x04))?;
        let opts = options(p.get(0x05))?;
        let pin_param = p.get(0x06).map(bytes).transpose()?;
        let pin_protocol = p.get(0x07).map(unsigned).transpose()?;

        // Step 1: zero-length pinUvAuthParam probe.
        if pin_param.is_some_and(<[u8]>::is_empty) {
            return Ok(self.wait_for_touch(Pending::PinProbe));
        }
        // Step 2.
        if pin_param.is_some() {
            Self::check_pin_protocol(pin_protocol)?;
        }
        // Step 4: no built-in UV, so "uv": true is INVALID_OPTION unless pinUvAuthParam
        // is present; "rk" is UNSUPPORTED_OPTION; "up" defaults to true.
        if opts.uv == Some(true) && pin_param.is_none() {
            return Err(status::INVALID_OPTION);
        }
        if opts.rk.is_some() {
            return Err(status::UNSUPPORTED_OPTION);
        }
        let up = opts.up.unwrap_or(true);
        // Step 5: with alwaysUv on and "up" true, an authenticator without a PIN answers
        // `CTAP2_ERR_PUAT_REQUIRED` (step 5.1.1: clientPin is supported for ga) and one with
        // a PIN needs a pinUvAuthToken, also `CTAP2_ERR_PUAT_REQUIRED` (step 5.5). Silent
        // ("up": false) assertions are not affected.
        if self.state.pin.always_uv && up && (!self.state.pin_is_set() || pin_param.is_none()) {
            return Err(status::PUAT_REQUIRED);
        }
        // Step 6: the pinUvAuthToken must verify over clientDataHash and carry the ga
        // permission for this RP.
        let uv = match pin_param {
            Some(param) => self.verify_for_rp(
                pin_protocol,
                param,
                &client_data_hash,
                permission::GA,
                rp_id,
                host.now(),
            )?,
            None => false,
        };
        let token = if uv { self.pin.token_serial() } else { None };

        // Step 7: locate the applicable credentials.
        let rp_id_hash = sha256(rp_id.as_bytes());
        let discoverable = allow_list.is_none();
        let ids: Vec<Vec<u8>> = match &allow_list {
            // 7.1: a present allowList; an empty one denotes no credential (catalog: "explicitly
            // present empty allowList returns NoCredentials"). 7.4: userVerificationRequired
            // credentials need UV.
            Some(list) => list
                .iter()
                .filter(|id| {
                    self.resolve(id, &rp_id_hash)
                        .is_some_and(|c| c.cred_protect != 3 || uv)
                })
                .take(1)
                .cloned()
                .collect(),
            // 7.2 / 7.5 / 12.2.1: discoverable credentials of this RP, newest first; without an
            // allowList, credProtect levels 2 and 3 need UV.
            None => self
                .state
                .residents
                .iter()
                .rev()
                .filter(|r| r.rp_id_hash == rp_id_hash && (r.cred_protect == 1 || uv))
                .map(|r| r.id.clone())
                .collect(),
        };
        // 7.6: before any touch and without using the counter.
        if ids.is_empty() {
            return Err(status::NO_CREDENTIALS);
        }
        // Step 10 extension checks, made before the touch so no touch is wasted:
        // §12.3 largeBlobKey must be true; §12.5 hmac-secret needs "up"
        // (catalog: "hmac-secret and up=false rejects with UnsupportedOption (0x2B)").
        if ext.large_blob_key == Some(false) {
            return Err(status::INVALID_OPTION);
        }
        if ext.hmac_secret.is_some() && !up {
            return Err(status::UNSUPPORTED_OPTION);
        }
        let hmac = ext
            .hmac_secret
            .as_ref()
            .map(|input| self.hmac_secret_salts(input, host))
            .transpose()?;

        let plan = Plan {
            client_data_hash,
            rp_id_hash,
            uv,
            ids,
            discoverable,
            ext,
            hmac,
            token,
        };
        if up {
            // Step 9: test of user presence.
            Ok(self.wait_for_touch(Pending::GetAssertion(Box::new(plan))))
        } else {
            Ok(Outcome::Done(self.finish_get_assertion(plan, false, host)))
        }
    }

    /// hmac-secret input processing (CTAP 2.1 §12.5 "authenticatorGetAssertion additional
    /// behaviors"), done before the touch so a bad input wastes none (model policy: §12.5
    /// processes extensions after user presence; the status codes are the same):
    /// - pinUvAuthProtocol (default 1) not supported: `CTAP2_ERR_PIN_AUTH_INVALID` (§12.5
    ///   states it for an absent value when protocol 1 is unsupported; applied to any
    ///   unsupported value);
    /// - `decapsulate(keyAgreement)` failing: `CTAP1_ERR_INVALID_PARAMETER` (§12.5 names no
    ///   status; the one §6.5.5 uses for decapsulate);
    /// - `verify(shared secret, saltEnc, saltAuth)` failing: `CTAP2_ERR_PIN_AUTH_INVALID`
    ///   ("If the verification fails, return CTAP2_ERR_PIN_AUTH_INVALID");
    /// - `decrypt(shared secret, saltEnc)` failing or not 32 / 64 bytes:
    ///   `CTAP1_ERR_INVALID_PARAMETER` ("If the decryption fails, or if the result is not
    ///   32 or 64 bytes long, return CTAP1_ERR_INVALID_PARAMETER").
    fn hmac_secret_salts(
        &mut self,
        input: &HmacSecretInput,
        host: &mut dyn Host,
    ) -> CtapResult<HmacSalts> {
        let protocol =
            PinProtocol::from_u64(input.protocol.unwrap_or(1)).ok_or(status::PIN_AUTH_INVALID)?;
        let shared = self.decapsulate(protocol, &input.key_agreement, host)?;
        if !protocol.verify(&shared, &input.salt_enc, &input.salt_auth) {
            return Err(status::PIN_AUTH_INVALID);
        }
        let salts = protocol
            .decrypt(&shared, &input.salt_enc)
            .filter(|s| s.len() == 32 || s.len() == 64)
            .ok_or(status::INVALID_PARAMETER)?;
        Ok(HmacSalts {
            protocol,
            shared,
            salts,
        })
    }

    /// Steps 11-13: sign with the first credential; keep getNextAssertion state when
    /// more discoverable credentials follow. When user presence was collected the
    /// pinUvAuthToken's UV flag and its permissions other than lbw are consumed (step 9).
    pub(crate) fn finish_get_assertion(
        &mut self,
        plan: Plan,
        up: bool,
        host: &mut dyn Host,
    ) -> Vec<u8> {
        if up {
            self.consume_token_after_presence();
        }
        let count = plan.ids.len();
        let include_count = plan.discoverable && count > 1;
        match self.assert_one(&plan, 0, up, include_count, host) {
            Ok(response) => {
                if include_count {
                    self.assertion = Some(NextAssertion {
                        plan,
                        next: 1,
                        up,
                        last: host.now(),
                    });
                }
                response
            }
            Err(code) => vec![code],
        }
    }

    /// `authenticatorGetNextAssertion` (CTAP 2.1 §6.3): `CTAP2_ERR_NOT_ALLOWED` without
    /// remembered state, after all credentials were served, more than 30 s after the
    /// previous assertion, or once the pinUvAuthToken that authenticated the
    /// getAssertion has expired (§6: the state "MUST" then be discarded).
    pub(crate) fn get_next_assertion(&mut self, host: &mut dyn Host) -> Vec<u8> {
        let Some(mut state) = self.assertion.take() else {
            return vec![status::NOT_ALLOWED];
        };
        let now = host.now();
        if now.saturating_sub(state.last) > NEXT_ASSERTION_TIMEOUT_MS
            || state.next >= state.plan.ids.len()
            || state
                .plan
                .token
                .is_some_and(|serial| !self.pin.token_still_valid(serial, now))
        {
            return vec![status::NOT_ALLOWED];
        }
        match self.assert_one(&state.plan, state.next, state.up, false, host) {
            Ok(response) => {
                state.next += 1;
                state.last = host.now();
                if state.next < state.plan.ids.len() {
                    self.assertion = Some(state);
                }
                response
            }
            Err(code) => {
                // Nothing was revealed; the same credential can be asked for again.
                self.assertion = Some(state);
                vec![code]
            }
        }
    }

    /// Sign one assertion with `plan.ids[index]`, advancing and persisting the global
    /// signature counter before the response that reveals it (`docs/DESIGN.md` §7). The
    /// counter refuses to roll over (`reference/legacy-v0.64-profiles.json`
    /// `counter_policy`: "refuses overflow"): at `u32::MAX` the answer is `CTAP1_ERR_OTHER`.
    fn assert_one(
        &mut self,
        plan: &Plan,
        index: usize,
        up: bool,
        include_count: bool,
        host: &mut dyn Host,
    ) -> CtapResult<Vec<u8>> {
        let id = plan.ids.get(index).ok_or(status::NOT_ALLOWED)?;
        let cred = self
            .resolve(id, &plan.rp_id_hash)
            .ok_or(status::NO_CREDENTIALS)?;
        let resident = self.state.residents.iter().find(|r| r.id == *id).cloned();
        let mut next = self.state.clone();
        next.counter = next.counter.checked_add(1).ok_or(status::OTHER)?;

        // Step 10: extension outputs. §12.2: the stored blob, or an empty byte string.
        let mut ext_out = MapBuilder::new();
        if plan.ext.cred_blob {
            let blob = resident
                .as_ref()
                .and_then(|r| r.cred_blob.clone())
                .unwrap_or_default();
            ext_out.set("credBlob", blob);
        }
        // §12.5: output1 = HMAC-SHA-256(CredRandom, salt1) [|| output2 with salt2], with
        // CredRandomWithUV when UV was performed, encrypted with the shared secret. Only
        // credentials created with hmac-secret have CredRandom values; for others the
        // extension is ignored.
        if let Some(hmac) = &plan.hmac
            && cred.hmac_secret
        {
            let key = cred.hmac_secret_key(plan.uv);
            let mut output = Vec::with_capacity(hmac.salts.len());
            for salt in hmac.salts.chunks(32) {
                output.extend_from_slice(&hmac_sha256(&key, salt));
            }
            let encrypted = hmac.protocol.encrypt(&hmac.shared, &output, host)?;
            ext_out.set("hmac-secret", encrypted);
        }
        let mut flags = 0;
        if up {
            flags |= FLAG_UP;
        }
        if plan.uv {
            flags |= FLAG_UV;
        }
        if !ext_out.is_empty() {
            flags |= FLAG_ED;
        }
        // WebAuthn L2 §6.1: rpIdHash || flags || signCount || extensions.
        let mut auth_data = Vec::with_capacity(64);
        auth_data.extend_from_slice(&plan.rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&next.counter.to_be_bytes());
        if !ext_out.is_empty() {
            auth_data.extend_from_slice(&ext_out.encode());
        }
        // Step 13.
        let signed = [auth_data.as_slice(), plan.client_data_hash.as_slice()].concat();
        let signature = cred.sign(&signed, host)?;
        self.commit(next, host)?;

        // §6.2.2 response: credential, authData, signature, user, numberOfCredentials,
        // largeBlobKey.
        let descriptor = MapBuilder::new()
            .insert("id", id.clone())
            .insert("type", PUBLIC_KEY)
            .build();
        let mut response = MapBuilder::new()
            .insert(0x01, descriptor)
            .insert(0x02, auth_data)
            .insert(0x03, signature);
        if let Some(r) = &resident {
            // User identifiable information only with UV, and only where the platform needs
            // it to let the user choose among several accounts; otherwise just the id.
            let mut user = MapBuilder::new().insert("id", r.user_id.clone());
            if plan.uv && plan.discoverable && plan.ids.len() > 1 {
                if let Some(name) = &r.user_name {
                    user.set("name", name.as_str());
                }
                if let Some(name) = &r.display_name {
                    user.set("displayName", name.as_str());
                }
            }
            response.set(0x04, user.build());
        }
        if include_count {
            response.set(0x05, plan.ids.len());
        }
        // §12.3: the credential's largeBlobKey at key 0x07, if it has one.
        if plan.ext.large_blob_key == Some(true)
            && let Some(key) = resident.as_ref().and_then(|r| r.large_blob_key)
        {
            response.set(0x07, key.to_vec());
        }
        Ok(ok(response.build()))
    }
}

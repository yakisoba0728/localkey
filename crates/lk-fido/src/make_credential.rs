//! `authenticatorMakeCredential` (CTAP 2.1 §6.1).
//!
//! Every check that can fail runs before the touch request; after the touch only key
//! generation, persistence and the response remain (CTAP 2.1 §6.1.2 steps 15-19).

use lk_codec::cbor::{MapBuilder, Value};
use lk_core::{Host, Outcome};
use lk_crypto::{SecretBytes, sha256};

use crate::client_pin::permission;
use crate::credential::{Alg, CredSecret};
use crate::get_info::{DISCOVERABLE_CAPACITY, MAX_CRED_BLOB_LENGTH};
use crate::request::{
    CtapResult, PUBLIC_KEY, Params, array, boolean, bytes, descriptor_ids, integer, map,
    optional_text, options, required, text, text_key, unsigned,
};
use crate::state::{LARGE_BLOB_KEY_LEN, Resident};
use crate::{Authenticator, Pending, ensure_keys, ok, status};

/// authenticatorData flags (WebAuthn L2 §6.1).
pub(crate) const FLAG_UP: u8 = 0x01;
pub(crate) const FLAG_UV: u8 = 0x04;
pub(crate) const FLAG_AT: u8 = 0x40;
pub(crate) const FLAG_ED: u8 = 0x80;

/// Longest stored RP name, user name and display name: authenticators may truncate a
/// `name` member (WebAuthn L2 §5.4.1, `PublicKeyCredentialEntity`, so also `rp.name`) and
/// `displayName` (§5.4.3) to 64 bytes; truncation keeps whole characters (§6.4.1).
pub(crate) const MAX_STORED_NAME: usize = 64;

/// Extension inputs of makeCredential (CTAP 2.1 §12).
#[derive(Debug, Default)]
struct Extensions {
    /// credProtect level when a supported level (1..=3) was requested (§12.1).
    cred_protect: Option<u8>,
    /// credBlob input (§12.2), secret ("additional, secret information", §6.10).
    cred_blob: Option<SecretBytes>,
    /// largeBlobKey input (§12.3).
    large_blob_key: Option<bool>,
    /// `"hmac-secret": true` (§12.5).
    hmac_secret: bool,
    /// `"minPinLength": true` (§12.4).
    min_pin_length: bool,
}

/// Parse the extensions map. Known extensions are type-checked
/// (`CTAP2_ERR_CBOR_UNEXPECTED_TYPE`); unknown ones are ignored (§6.1.2 step 15, §8).
/// A credProtect value outside 1..=3 is ignored as an input the authenticator does not
/// understand (model policy; §12.1 defines only these levels), so no output is produced
/// for it ("MUST NOT return an unsolicited credProtect extension output").
fn extensions(value: Option<&Value>) -> CtapResult<Extensions> {
    let mut ext = Extensions::default();
    let Some(value) = value else { return Ok(ext) };
    for (key, v) in map(value)? {
        match key.as_text() {
            Some("credProtect") => {
                let level = unsigned(v)?;
                ext.cred_protect = u8::try_from(level).ok().filter(|l| (1..=3).contains(l));
            }
            Some("credBlob") => ext.cred_blob = Some(SecretBytes::from_slice(bytes(v)?)),
            Some("largeBlobKey") => ext.large_blob_key = Some(boolean(v)?),
            Some("hmac-secret") => ext.hmac_secret = boolean(v)?,
            Some("minPinLength") => ext.min_pin_length = boolean(v)?,
            _ => {}
        }
    }
    Ok(ext)
}

/// A validated makeCredential waiting for the touch.
#[derive(Debug)]
pub(crate) struct Plan {
    client_data_hash: Vec<u8>,
    rp_id: String,
    /// `rp.name`, stored with a discoverable credential for enumerateRPs (§6.8.3).
    rp_name: Option<String>,
    rp_id_hash: [u8; 32],
    user_id: Vec<u8>,
    user_name: Option<String>,
    display_name: Option<String>,
    alg: Alg,
    rk: bool,
    uv: bool,
    ext: Extensions,
}

/// Cut `text` to at most `max` bytes on a character boundary (WebAuthn L2 §6.4.1).
pub(crate) fn truncate(text: Option<String>, max: usize) -> Option<String> {
    text.map(|mut t| {
        if t.len() > max {
            let mut end = max;
            while !t.is_char_boundary(end) {
                end -= 1;
            }
            t.truncate(end);
        }
        t
    })
}

impl Authenticator {
    pub(crate) fn make_credential(
        &mut self,
        params: &[u8],
        host: &mut dyn Host,
    ) -> Outcome<Vec<u8>> {
        match self.prepare_make_credential(params, host) {
            Ok(outcome) => outcome,
            Err(code) => Outcome::Done(vec![code]),
        }
    }

    /// CTAP 2.1 §6.1.2 steps 1-14 up to the touch request.
    fn prepare_make_credential(
        &mut self,
        params: &[u8],
        host: &mut dyn Host,
    ) -> CtapResult<Outcome<Vec<u8>>> {
        // §6.1.1 parameters: decode and type-check everything first.
        let p = Params::decode(params)?;
        let client_data_hash = bytes(required(p.get(0x01))?)?.to_vec();
        let rp = map(required(p.get(0x02))?)?;
        let rp_id = text(required(text_key(rp, "id"))?)?.to_owned();
        let rp_name = optional_text(rp, "name")?;
        let user = map(required(p.get(0x03))?)?;
        let user_id = bytes(required(text_key(user, "id"))?)?.to_vec();
        let user_name = optional_text(user, "name")?;
        let display_name = optional_text(user, "displayName")?;
        optional_text(user, "icon")?;
        let cred_params = array(required(p.get(0x04))?)?;
        // Step 3: every element must be well-formed; the first supported "public-key"
        // algorithm wins; unknown types are skipped.
        let mut chosen = None;
        for item in cred_params {
            let entry = map(item)?;
            let kind = text(required(text_key(entry, "type"))?)?;
            let alg = integer(required(text_key(entry, "alg"))?)?;
            if chosen.is_none() && kind == PUBLIC_KEY {
                chosen = Alg::from_cose(alg);
            }
        }
        let exclude = p
            .get(0x05)
            .map(descriptor_ids)
            .transpose()?
            .unwrap_or_default();
        let ext = extensions(p.get(0x06))?;
        let opts = options(p.get(0x07))?;
        let pin_param = p.get(0x08).map(bytes).transpose()?;
        let pin_protocol = p.get(0x09).map(unsigned).transpose()?;
        let enterprise = p.get(0x0A).map(unsigned).transpose()?;

        // Step 1: a zero-length pinUvAuthParam asks for a touch, then reports PIN status.
        if pin_param.is_some_and(<[u8]>::is_empty) {
            return Ok(self.wait_for_touch(Pending::PinProbe));
        }
        // Step 2.
        if pin_param.is_some() {
            Self::check_pin_protocol(pin_protocol)?;
        }
        // Step 3 result.
        let alg = chosen.ok_or(status::UNSUPPORTED_ALGORITHM)?;
        // Step 5: no built-in UV ("uv" absent from GetInfo options), so "uv": true is
        // INVALID_OPTION unless pinUvAuthParam is present (then uv counts as false);
        // "rk" is supported; "up": false is INVALID_OPTION.
        if opts.uv == Some(true) && pin_param.is_none() {
            return Err(status::INVALID_OPTION);
        }
        let rk = opts.rk.unwrap_or(false);
        if opts.up == Some(false) {
            return Err(status::INVALID_OPTION);
        }
        // Step 6: with alwaysUv on, an authenticator without a PIN cannot verify the user:
        // "If the clientPin option ID is present and noMcGaPermissionsWithClientPin option
        // ID is absent or false ... End the operation by returning CTAP2_ERR_PUAT_REQUIRED"
        // (step 6.2.1; GetInfo lists clientPin, false). With a PIN and no pinUvAuthParam it
        // is also `CTAP2_ERR_PUAT_REQUIRED` (step 6.4, below).
        if self.state.pin.always_uv && !self.state.pin_is_set() {
            return Err(status::PUAT_REQUIRED);
        }
        // Step 7: with makeCredUvNotRqd, a PIN-protected authenticator still requires a
        // pinUvAuthToken for discoverable credentials (and for every credential while
        // alwaysUv is on, when makeCredUvNotRqd is false).
        if self.state.pin_is_set() && pin_param.is_none() && (rk || self.state.pin.always_uv) {
            return Err(status::PUAT_REQUIRED);
        }
        // Step 9: not enterprise attestation capable (GetInfo has no "ep"): any unsigned
        // value is CTAP1_ERR_INVALID_PARAMETER, another type was rejected above
        // (`reference/BEHAVIOR_CATALOG.md` FIDO: "unsupported capability returns 02 and wrong
        // boolean type returns 11").
        if enterprise.is_some() {
            return Err(status::INVALID_PARAMETER);
        }
        // Step 11: the pinUvAuthToken must verify over clientDataHash and carry the mc
        // permission for this RP.
        let uv = match pin_param {
            Some(param) => self.verify_for_rp(
                pin_protocol,
                param,
                &client_data_hash,
                permission::MC,
                &rp_id,
                host.now(),
            )?,
            None => false,
        };
        // §12.3: largeBlobKey must be true and needs rk.
        if let Some(large_blob_key) = ext.large_blob_key
            && (!large_blob_key || !rk)
        {
            return Err(status::INVALID_OPTION);
        }
        let rp_id_hash = sha256(rp_id.as_bytes());
        // Step 12: an excluded credential of this RP ends the command after a touch; a
        // userVerificationRequired credential counts only when UV was performed.
        for id in &exclude {
            if let Some(cred) = self.resolve(id, &rp_id_hash)
                && (cred.cred_protect != 3 || uv)
            {
                return Ok(self.wait_for_touch(Pending::Excluded));
            }
        }
        // Step 14: test of user presence.
        let plan = Plan {
            client_data_hash,
            rp_id,
            rp_name: truncate(rp_name.filter(|n| !n.is_empty()), MAX_STORED_NAME),
            rp_id_hash,
            user_id,
            user_name: truncate(user_name, MAX_STORED_NAME),
            display_name: truncate(display_name, MAX_STORED_NAME),
            alg,
            rk,
            uv,
            ext,
        };
        Ok(self.wait_for_touch(Pending::MakeCredential(Box::new(plan))))
    }

    /// Steps 15-19 after the touch: create the credential, persist what changed and
    /// return `{1: "packed", 2: authData, 3: attStmt, 5?: largeBlobKey}`. User presence was
    /// collected, so the pinUvAuthToken's UV flag and its permissions other than lbw are
    /// consumed (step 14).
    pub(crate) fn finish_make_credential(&mut self, plan: Plan, host: &mut dyn Host) -> Vec<u8> {
        self.consume_token_after_presence();
        match self.create_credential(plan, host) {
            Ok(response) => response,
            Err(code) => vec![code],
        }
    }

    fn create_credential(&mut self, plan: Plan, host: &mut dyn Host) -> CtapResult<Vec<u8>> {
        let mut next = self.state.clone();
        let keys_changed = ensure_keys(&mut next, host)?;
        let secret = next.secret.clone().ok_or(status::OTHER)?;

        // §12.1: level 1 (userVerificationOptional) is the default.
        let cred_protect = plan.ext.cred_protect.unwrap_or(1);
        let mut cred = CredSecret::generate(plan.alg, cred_protect, plan.rk, host);
        cred.hmac_secret = plan.ext.hmac_secret;
        let id = cred.wrap(&secret, &plan.rp_id_hash, host)?;

        // Extension outputs (§12) in authenticatorData.
        let mut ext_out = MapBuilder::new();
        if let Some(level) = plan.ext.cred_protect {
            ext_out.set("credProtect", level);
        }
        // §12.2: the blob is stored only for a discoverable credential and only up to
        // maxCredBlobLength (`reference/legacy-v0.64-profiles.json` `credBlob_policy`:
        // "new registration stores only for discoverable keys").
        let stored_blob = match plan.ext.cred_blob {
            None => None,
            Some(blob) => {
                let storable = plan.rk && blob.len() <= MAX_CRED_BLOB_LENGTH;
                ext_out.set("credBlob", storable);
                storable.then_some(blob)
            }
        };
        // §12.5: the credential records that it has CredRandom values.
        if plan.ext.hmac_secret {
            ext_out.set("hmac-secret", true);
        }
        // §12.4: reported only to RPs on the minPinLengthRPIDs list.
        if plan.ext.min_pin_length && next.pin.min_pin_rp_ids.contains(&plan.rp_id) {
            ext_out.set("minPinLength", next.pin.min_length);
        }
        // §12.3: 32 random bytes kept with the discoverable credential.
        let large_blob_key = plan.ext.large_blob_key.map(|_| {
            let mut key = SecretBytes::zeroed(LARGE_BLOB_KEY_LEN);
            host.fill(&mut key);
            key
        });

        if plan.rk {
            // Step 17: replace a credential of the same RP and user, else need room.
            next.residents
                .retain(|r| !(r.rp_id_hash == plan.rp_id_hash && r.user_id == plan.user_id));
            if next.residents.len() >= DISCOVERABLE_CAPACITY {
                return Err(status::KEY_STORE_FULL);
            }
            next.residents.push(Resident {
                id: id.clone(),
                rp_id: plan.rp_id.clone(),
                rp_name: plan.rp_name.clone(),
                rp_id_hash: plan.rp_id_hash,
                user_id: plan.user_id.clone(),
                user_name: plan.user_name.clone(),
                display_name: plan.display_name.clone(),
                cred_blob: stored_blob,
                large_blob_key: large_blob_key.clone(),
                cred_protect,
            });
        }

        // WebAuthn L2 §6.1 / §6.5.1: authenticatorData with attested credential data. The
        // shared counter is reported, not advanced: registration leaves the store unchanged
        // (`reference/legacy-v0.64-profiles.json` `counter_policy`; catalog "initialized
        // store remains constant").
        let ext_present = !ext_out.is_empty();
        let mut flags = FLAG_UP | FLAG_AT;
        if plan.uv {
            flags |= FLAG_UV;
        }
        if ext_present {
            flags |= FLAG_ED;
        }
        let aaguid = host.profile().aaguid;
        let mut auth_data = Vec::with_capacity(512);
        auth_data.extend_from_slice(&plan.rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&next.counter.to_be_bytes());
        auth_data.extend_from_slice(&aaguid);
        let id_len = u16::try_from(id.len()).map_err(|_| status::OTHER)?;
        auth_data.extend_from_slice(&id_len.to_be_bytes());
        auth_data.extend_from_slice(&id);
        lk_codec::cbor::encode_into(&cred.cose_public_key(), &mut auth_data);
        if ext_present {
            auth_data.extend_from_slice(&ext_out.encode());
        }

        // WebAuthn L2 §8.2 packed attestation with the attestation certificate:
        // sig over authenticatorData || clientDataHash, alg -7 (the attestation key's).
        let attestation = next.attestation.as_ref().ok_or(status::OTHER)?;
        let signed = [auth_data.as_slice(), plan.client_data_hash.as_slice()].concat();
        let sig = attestation.sign(&signed, host)?;
        let att_stmt = MapBuilder::new()
            .insert("alg", Alg::Es256.cose())
            .insert("sig", sig)
            .insert(
                "x5c",
                Value::Array(vec![Value::Bytes(attestation.cert.clone())]),
            )
            .build();

        if plan.rk || keys_changed {
            self.commit(next, host)?;
        }
        let mut response = MapBuilder::new()
            .insert(0x01, "packed")
            .insert(0x02, auth_data)
            .insert(0x03, att_stmt);
        if let Some(key) = large_blob_key {
            response.set(0x05, key.to_vec());
        }
        Ok(ok(response.build()))
    }
}

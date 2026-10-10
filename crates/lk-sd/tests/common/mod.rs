//! An independent SCP03 off-card entity (host) for the integration tests.
//!
//! Written from GlobalPlatform Card Specification v2.3.1 Amendment D v1.1.2 ("Amd D")
//! without using any `lk-sd` code: §4.1.5 KDF data layout, §6.2.1 session keys, §6.2.2
//! cryptograms, §7.1.2 EXTERNAL AUTHENTICATE, §6.2.4 C-MAC, §6.2.6 command encryption,
//! §6.2.5 R-MAC and §6.2.7 response decryption. Only `lk_crypto` primitives are shared.
//! APDUs are encoded by hand (ISO/IEC 7816-4 §5.1) rather than through `lk_codec`.

#![allow(dead_code, clippy::unwrap_used, clippy::too_many_arguments)]

pub mod scp11;

use lk_core::{CardApplet, Host, Outcome};
use lk_sd::{SecureChannel, SecurityDomain};

/// Decode a hex string, ignoring whitespace.
pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Yubico's published default SCP03 key (yk5-apps-scp: "404142434445464748494a4b4c4d4e4f
/// for all three keys").
pub const DEFAULT_KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

#[derive(Clone, Copy, Debug)]
pub struct StaticKeys {
    pub enc: [u8; 16],
    pub mac: [u8; 16],
    pub dek: [u8; 16],
}

impl StaticKeys {
    pub const DEFAULT: StaticKeys = StaticKeys { enc: DEFAULT_KEY, mac: DEFAULT_KEY, dek: DEFAULT_KEY };

    /// Distinct keys derived from one byte, for tests that need many sets.
    pub fn from_seed(seed: u8) -> StaticKeys {
        let mk = |offset: u8| core::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(offset).wrapping_add(i as u8));
        StaticKeys { enc: mk(0x10), mac: mk(0x50), dek: mk(0x90) }
    }
}

pub fn cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    lk_crypto::aes_cmac(key, data).unwrap()
}

/// Amd D §4.1.5: `00 x 11 || constant || 00 || L (bits, 2 bytes) || i || context`,
/// concatenating counter blocks until `bits` are produced.
pub fn derive(key: &[u8; 16], constant: u8, context: &[u8], bits: u16) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 1u8;
    while out.len() * 8 < usize::from(bits) {
        let mut data = vec![0u8; 11];
        data.push(constant);
        data.push(0x00);
        data.extend_from_slice(&bits.to_be_bytes());
        data.push(i);
        data.extend_from_slice(context);
        out.extend_from_slice(&cmac(key, &data));
        i += 1;
    }
    out.truncate(usize::from(bits) / 8);
    out
}

fn key16(v: Vec<u8>) -> [u8; 16] {
    v.try_into().unwrap()
}

/// ISO/IEC 9797-1 method 2.
pub fn pad(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    while !out.len().is_multiple_of(16) {
        out.push(0);
    }
    out
}

pub fn unpad(data: &[u8]) -> Option<Vec<u8>> {
    let end = data.iter().rposition(|&b| b != 0)?;
    (data[end] == 0x80).then(|| data[..end].to_vec())
}

/// AES key check value: first 3 bytes of AES(key, 01 x 16).
pub fn kcv(key: &[u8; 16]) -> [u8; 3] {
    let b = lk_crypto::aes_ecb_encrypt_block(key, &[1u8; 16]).unwrap();
    [b[0], b[1], b[2]]
}

/// Encode a command APDU (ISO/IEC 7816-4 §5.1). `le`: `None` absent, `Some(n)` written
/// as is (0 = maximum).
pub fn encode_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u16>, extended: bool) -> Vec<u8> {
    let mut out = vec![cla, ins, p1, p2];
    if extended {
        if !data.is_empty() || le.is_some() {
            out.push(0);
        }
        if !data.is_empty() {
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        if let Some(le) = le {
            out.extend_from_slice(&le.to_be_bytes());
        }
    } else {
        if !data.is_empty() {
            assert!(data.len() <= 255);
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        if let Some(le) = le {
            out.push(le as u8);
        }
    }
    out
}

/// INITIALIZE UPDATE as Yubico's SDK sends it: `80 50 KVN 00 08 <challenge>`, no Le.
pub fn init_update_apdu(kvn: u8, host_challenge: &[u8; 8]) -> Vec<u8> {
    encode_apdu(0x80, 0x50, kvn, 0x00, host_challenge, None, false)
}

/// The host side after INITIALIZE UPDATE.
#[derive(Clone, Debug)]
pub struct PendingHost {
    pub kvn: u8,
    pub context: Vec<u8>,
    pub s_enc: [u8; 16],
    pub s_mac: [u8; 16],
    pub s_rmac: [u8; 16],
    pub card_cryptogram_ok: bool,
    pub dek: [u8; 16],
}

/// Parse an INITIALIZE UPDATE response (Amd D §7.1.1.3): diversification data (10),
/// key information (KVN, `03`, `i`), card challenge (8), card cryptogram (8), `9000`.
pub fn read_init_response(keys: &StaticKeys, host_challenge: &[u8; 8], resp: &[u8]) -> PendingHost {
    assert_eq!(resp.len(), 31, "INITIALIZE UPDATE response {resp:02X?}");
    assert_eq!(&resp[29..], &[0x90, 0x00]);
    assert_eq!(&resp[11..13], &[0x03, 0x60], "SCP identifier 03, i = 60");
    let kvn = resp[10];
    let card_challenge = &resp[13..21];
    let card_cryptogram = &resp[21..29];
    let mut context = host_challenge.to_vec();
    context.extend_from_slice(card_challenge);
    let s_enc = key16(derive(&keys.enc, 0x04, &context, 128));
    let s_mac = key16(derive(&keys.mac, 0x06, &context, 128));
    let s_rmac = key16(derive(&keys.mac, 0x07, &context, 128));
    let expected = derive(&s_mac, 0x00, &context, 64);
    PendingHost {
        kvn,
        context,
        s_enc,
        s_mac,
        s_rmac,
        card_cryptogram_ok: expected == card_cryptogram,
        dek: keys.dek,
    }
}

impl PendingHost {
    pub fn host_cryptogram(&self) -> Vec<u8> {
        derive(&self.s_mac, 0x01, &self.context, 64)
    }

    /// EXTERNAL AUTHENTICATE (Amd D §7.1.2) with `cryptogram`, MAC over
    /// `MCV(0) || 84 82 P1 00 10 || cryptogram`. Returns the APDU and the host session.
    pub fn external_authenticate_with(&self, level: u8, cryptogram: &[u8]) -> (Vec<u8>, HostSession) {
        self.external_authenticate_form(level, cryptogram, false, false)
    }

    /// EXTERNAL AUTHENTICATE in a chosen length form. `extended` sends the extended form
    /// (`84 82 P1 00 00 00 10 ...`, as yubikit does on a session configured for
    /// extended APDUs: `ScpProcessor.send_apdu` formats the APDU with the session
    /// formatter and MACs everything before the MAC placeholder). `mac_extended` picks
    /// the Lc form the C-MAC covers (Amd D §6.2.4: the header and Lc as sent).
    pub fn external_authenticate_form(&self, level: u8, cryptogram: &[u8], extended: bool, mac_extended: bool) -> (Vec<u8>, HostSession) {
        let mut input = vec![0u8; 16];
        input.extend_from_slice(&[0x84, 0x82, level, 0x00]);
        if mac_extended {
            input.extend_from_slice(&[0x00, 0x00, 0x10]);
        } else {
            input.push(0x10);
        }
        input.extend_from_slice(cryptogram);
        let full = cmac(&self.s_mac, &input);
        let mut data = cryptogram.to_vec();
        data.extend_from_slice(&full[..8]);
        let apdu = encode_apdu(0x84, 0x82, level, 0x00, &data, extended.then_some(0), extended);
        let session = HostSession {
            s_enc: self.s_enc,
            s_mac: self.s_mac,
            s_rmac: self.s_rmac,
            mcv: full,
            counter: 1,
            level,
            pad_empty: true,
            dek: self.dek,
        };
        (apdu, session)
    }

    pub fn external_authenticate(&self, level: u8) -> (Vec<u8>, HostSession) {
        self.external_authenticate_with(level, &self.host_cryptogram())
    }
}

/// An established host session.
#[derive(Clone, Debug)]
pub struct HostSession {
    pub s_enc: [u8; 16],
    pub s_mac: [u8; 16],
    pub s_rmac: [u8; 16],
    pub mcv: [u8; 16],
    pub counter: u128,
    pub level: u8,
    /// Encrypt an empty data field as one padding block, as Yubico's SDK does; when
    /// false an empty field is sent empty (the counter still advances).
    pub pad_empty: bool,
    pub dek: [u8; 16],
}

impl HostSession {
    /// Wrap a command (Amd D §6.2.6 then §6.2.4).
    pub fn wrap(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u16>, extended: bool) -> Vec<u8> {
        let mut body = data.to_vec();
        if self.level & 0x02 != 0 {
            let counter = self.counter;
            self.counter += 1;
            if !data.is_empty() || self.pad_empty {
                let icv = lk_crypto::aes_ecb_encrypt_block(&self.s_enc, &counter.to_be_bytes()).unwrap();
                body = lk_crypto::aes_cbc_encrypt(&self.s_enc, &icv, &pad(data)).unwrap();
            }
        }
        let cla = cla | 0x04;
        let lc = body.len() + 8;
        let mut input = self.mcv.to_vec();
        input.extend_from_slice(&[cla, ins, p1, p2]);
        if extended {
            input.push(0);
            input.extend_from_slice(&(lc as u16).to_be_bytes());
        } else {
            input.push(lc as u8);
        }
        input.extend_from_slice(&body);
        self.mcv = cmac(&self.s_mac, &input);
        body.extend_from_slice(&self.mcv[..8]);
        encode_apdu(cla, ins, p1, p2, &body, le, extended)
    }

    /// Verify and decrypt a response (Amd D §6.2.5, §6.2.7). Error statuses must come
    /// bare.
    pub fn unwrap(&self, resp: &[u8]) -> Result<(Vec<u8>, u16), String> {
        if resp.len() < 2 {
            return Err("short response".into());
        }
        let (data, sw) = resp.split_at(resp.len() - 2);
        let sw = u16::from_be_bytes([sw[0], sw[1]]);
        let protected = sw == 0x9000 || matches!(sw >> 8, 0x61..=0x63);
        if !protected {
            return if data.is_empty() { Ok((Vec::new(), sw)) } else { Err("error status with data".into()) };
        }
        let mut data = data.to_vec();
        if self.level & 0x10 != 0 {
            if data.len() < 8 {
                return Err("missing R-MAC".into());
            }
            let mac = data.split_off(data.len() - 8);
            let mut input = self.mcv.to_vec();
            input.extend_from_slice(&data);
            input.extend_from_slice(&sw.to_be_bytes());
            if cmac(&self.s_rmac, &input)[..8] != mac[..] {
                return Err("bad R-MAC".into());
            }
        }
        if self.level & 0x20 != 0 && !data.is_empty() {
            let mut block = (self.counter - 1).to_be_bytes();
            block[0] = 0x80;
            let icv = lk_crypto::aes_ecb_encrypt_block(&self.s_enc, &block).unwrap();
            let clear = lk_crypto::aes_cbc_decrypt(&self.s_enc, &icv, &data).map_err(|_| "bad length".to_string())?;
            data = unpad(&clear).ok_or("bad padding")?;
        }
        Ok((data, sw))
    }

    /// The PUT KEY data for a whole SCP03 set (GP 2.3.1 §11.8.2.3): new KVN, then for
    /// ENC, MAC, DEK `88 10 <AES-CBC(DEK, key), zero ICV> 03 <KCV>`.
    pub fn put_key_data(&self, new_kvn: u8, keys: &StaticKeys) -> Vec<u8> {
        put_key_data(&self.dek, new_kvn, keys)
    }
}

pub fn put_key_data(dek: &[u8; 16], new_kvn: u8, keys: &StaticKeys) -> Vec<u8> {
    let mut data = vec![new_kvn];
    for k in [keys.enc, keys.mac, keys.dek] {
        data.extend_from_slice(&[0x88, 0x10]);
        data.extend_from_slice(&lk_crypto::aes_cbc_encrypt(dek, &[0u8; 16], &k).unwrap());
        data.push(3);
        data.extend_from_slice(&kcv(&k));
    }
    data
}

/// Expected PUT KEY response data: KVN || KCV(ENC) || KCV(MAC) || KCV(DEK).
pub fn put_key_response(new_kvn: u8, keys: &StaticKeys) -> Vec<u8> {
    let mut out = vec![new_kvn];
    for k in [keys.enc, keys.mac, keys.dek] {
        out.extend_from_slice(&kcv(&k));
    }
    out
}

/// Open an SCP03 session: INITIALIZE UPDATE + EXTERNAL AUTHENTICATE through
/// `SecurityDomain::handshake`. Panics if any step fails.
pub fn open(sd: &mut SecurityDomain, host: &mut dyn Host, keys: &StaticKeys, kvn: u8, level: u8) -> (HostSession, SecureChannel) {
    let challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let (resp, ch) = sd.handshake(&init_update_apdu(kvn, &challenge), host);
    assert!(ch.is_none());
    let pending = read_init_response(keys, &challenge, &resp);
    assert!(pending.card_cryptogram_ok, "card cryptogram");
    if kvn != 0 {
        assert_eq!(pending.kvn, kvn, "INITIALIZE UPDATE key information names the selected version");
    }
    let (apdu, session) = pending.external_authenticate(level);
    let (resp, ch) = sd.handshake(&apdu, host);
    assert_eq!(resp, vec![0x90, 0x00]);
    (session, ch.expect("channel"))
}

/// What `lk-device` does for one command while the Security Domain is selected and a
/// channel is open: unwrap, dispatch (handshakes to `handshake`, others to
/// `process_secure`), wrap.
pub fn device_transmit(sd: &mut SecurityDomain, channel: &mut SecureChannel, host: &mut dyn Host, apdu: &[u8]) -> Vec<u8> {
    let plain = match channel.unwrap_command(apdu) {
        Ok(plain) => plain,
        Err(sw) => return sw.to_be_bytes().to_vec(),
    };
    let resp = if lk_sd::is_handshake(&plain) {
        sd.handshake(&plain, host).0
    } else if plain.get(1..3) == Some(&[0xA4, 0x04]) {
        // docs/CONTRACTS.md: only `xx A4 04 xx` is SELECT.
        sd.select(&plain, host)
    } else {
        match sd.process_secure(&plain, channel, host) {
            Outcome::Done(r) => r,
            Outcome::NeedTouch { .. } => panic!("the Security Domain never needs touch"),
        }
    };
    channel.wrap_response(&resp)
}

/// Host wrap + device transmit + host unwrap.
pub fn send(
    sd: &mut SecurityDomain,
    channel: &mut SecureChannel,
    host: &mut dyn Host,
    session: &mut HostSession,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> (Vec<u8>, u16) {
    let apdu = session.wrap(cla, ins, p1, p2, data, Some(0), false);
    let resp = device_transmit(sd, channel, host, &apdu);
    session.unwrap(&resp).unwrap()
}

/// Like [`send`], in the extended length form (for data longer than a short APDU).
pub fn send_ext(
    sd: &mut SecurityDomain,
    channel: &mut SecureChannel,
    host: &mut dyn Host,
    session: &mut HostSession,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> (Vec<u8>, u16) {
    let apdu = session.wrap(cla, ins, p1, p2, data, Some(0), true);
    let resp = device_transmit(sd, channel, host, &apdu);
    session.unwrap(&resp).unwrap()
}

/// A handshake command as `lk-device` handles it: unwrapped by the current channel (if
/// any), given to `SecurityDomain::handshake`, its response wrapped by the current
/// channel; a new channel is returned to replace the current one.
pub fn device_handshake(
    sd: &mut SecurityDomain,
    outer: Option<&mut SecureChannel>,
    host: &mut dyn Host,
    apdu: &[u8],
) -> (Vec<u8>, Option<SecureChannel>) {
    match outer {
        None => sd.handshake(apdu, host),
        Some(channel) => {
            let plain = match channel.unwrap_command(apdu) {
                Ok(plain) => plain,
                Err(sw) => return (sw.to_be_bytes().to_vec(), None),
            };
            let (resp, new) = sd.handshake(&plain, host);
            (channel.wrap_response(&resp), new)
        }
    }
}

/// A plaintext command through `CardApplet::process`.
pub fn plain(sd: &mut SecurityDomain, host: &mut dyn Host, apdu: &[u8]) -> Vec<u8> {
    match sd.process(apdu, host) {
        Outcome::Done(r) => r,
        Outcome::NeedTouch { .. } => panic!("no touch"),
    }
}

pub fn status(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]])
}

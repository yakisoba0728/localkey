//! YubiHSM Auth application: stored symmetric (SCP03 derivation) and asymmetric
//! credentials, session-key calculation, credential password retries, management key
//! and touch policy.
//!
//! # Sources
//!
//! The command set, tags, lengths and status words follow Yubico's public YubiHSM Auth
//! documentation as implemented by its public host SDKs:
//!
//! - yubikit-python `yubikit/hsmauth.py` (`HsmAuthSession`): instruction and tag values,
//!   `MANAGEMENT_KEY_LEN = 16`, `CREDENTIAL_PASSWORD_LEN = 16`, labels of 1–64 bytes,
//!   `INITIAL_RETRY_COUNTER = 8`, the LIST entry layout, `RESET` as `00 06 DE AD`, the
//!   firmware-version gates (asymmetric credentials and GET CHALLENGE from 5.6.0, the
//!   GET CHALLENGE password from 5.7.1, CHANGE CREDENTIAL PASSWORD from 5.8.0).
//! - ykman `ykman/_cli/hsmauth.py` (`handle_error`): `6983` duplicate label or "not an
//!   asymmetric credential", `6A84` no space, `6A82` credential not found, `6982` not
//!   touched; `63Cx` wrong management key / credential password with `x` tries left.
//! - yubihsm-shell `ykhsmauth/ykhsmauth.c`: GET VERSION answers the three raw version
//!   bytes; `translate_error` maps `6A80` to invalid parameters.
//! - yubihsm-shell `lib/yubihsm.c` (`yh_create_session_asym`, `yh_finish_create_session`):
//!   the YubiHSM 2 session derivations this application computes on the host's behalf
//!   (detailed in the private `kdf` module): the asymmetric shared secrets, the X9.63
//!   shared info `3C 88 10`, the key split and the receipt input `EPK.SD || EPK.OCE`.
//! - yubihsm-shell `ykhsmauth/ykhsmauth.h`: the status-word names (`6982`
//!   `SW_SECURITY_STATUS_NOT_SATISFIED` → touch error, `6984` `SW_DATA_INVALID`, `6A84`
//!   `SW_FILE_FULL`, `63Cx` `SW_AUTHENTICATION_FAILED`).
//! - Yubico .NET SDK (YESDK) `Yubico.YubiKey/YubiHsmAuth` and its user's manual: 32
//!   credentials, labels of 1–64 UTF-8 bytes (NUL allowed), 8 tries for the management
//!   key (blocked until RESET) and for each credential password (the credential is
//!   permanently deleted after the eighth wrong one), a correct secret restoring 8
//!   tries, touch only for session-key calculation, and "the credential password retry
//!   count is not changed" when the touch fails; `6984` (`ReferenceDataUnusable`) as
//!   "invalid authentication data".
//! - yubikit `generate_credential_asymmetric`: on-device generation is a PUT with an
//!   empty `7D` ("Empty byte will generate key").
//!
//! Key derivation follows GlobalPlatform Card Specification v2.3.1 Amendment D (SCP03)
//! §4.1.5 with NIST SP 800-108 counter mode, and SEC 1 v2.0 §3.6.1 (ANSI X9.63 KDF) for
//! the asymmetric variant. Where no public source fixes a behaviour, the choice is a
//! documented model decision ("Model decision" in the item docs) and is listed in
//! `docs/catalog/hsmauth.md`.
//!
//! This application produces no ECDSA signatures (it only performs ECDH), so the
//! hedged-signature rule of `docs/CONTRACTS.md` does not apply to it.

#![forbid(unsafe_code)]

mod applet;
mod kdf;
mod request;
mod state;

pub use applet::HsmAuth;

use lk_core::Millis;

/// Application identifier of YubiHSM Auth (yubikit `AID.HSMAUTH`).
pub const AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01];

/// Instruction bytes (yubikit `hsmauth.py` `INS_*`).
pub mod ins {
    /// Store, import or generate a credential.
    pub const PUT: u8 = 0x01;
    /// Delete a credential.
    pub const DELETE: u8 = 0x02;
    /// Calculate session keys.
    pub const CALCULATE: u8 = 0x03;
    /// Host challenge (symmetric) or ephemeral public key (asymmetric).
    pub const GET_CHALLENGE: u8 = 0x04;
    /// List credentials.
    pub const LIST: u8 = 0x05;
    /// Factory-reset the application (`P1 P2 = DE AD`).
    pub const RESET: u8 = 0x06;
    /// Firmware version as three raw bytes.
    pub const GET_VERSION: u8 = 0x07;
    /// Change the management key.
    pub const PUT_MANAGEMENT_KEY: u8 = 0x08;
    /// Remaining management key tries.
    pub const GET_MANAGEMENT_KEY_RETRIES: u8 = 0x09;
    /// Public key of an asymmetric credential.
    pub const GET_PUBLIC_KEY: u8 = 0x0A;
    /// CHANGE CREDENTIAL PASSWORD: firmware 5.8.0 and later only (yubikit
    /// `require_version(self.version, (5, 8, 0))`); not supported by 5.7.4.
    pub const CHANGE_CREDENTIAL_PASSWORD: u8 = 0x0B;
    /// GET RESPONSE (ISO/IEC 7816-4 §7.6.1).
    pub const GET_RESPONSE: u8 = 0xC0;
}

/// Data object tags (yubikit `hsmauth.py` `TAG_*`).
pub mod tag {
    pub const LABEL: u32 = 0x71;
    pub const LABEL_LIST: u32 = 0x72;
    pub const CREDENTIAL_PASSWORD: u32 = 0x73;
    pub const ALGORITHM: u32 = 0x74;
    pub const KEY_ENC: u32 = 0x75;
    pub const KEY_MAC: u32 = 0x76;
    pub const CONTEXT: u32 = 0x77;
    pub const RESPONSE: u32 = 0x78;
    pub const VERSION: u32 = 0x79;
    pub const TOUCH: u32 = 0x7A;
    pub const MANAGEMENT_KEY: u32 = 0x7B;
    pub const PUBLIC_KEY: u32 = 0x7C;
    pub const PRIVATE_KEY: u32 = 0x7D;
}

/// Credential algorithms (yubikit `hsmauth.ALGORITHM`, YubiHSM 2 algorithm numbers).
pub mod alg {
    /// AES-128 K-ENC/K-MAC pair, symmetric YubiHSM 2 authentication.
    pub const AES128_YUBICO_AUTHENTICATION: u8 = 38;
    /// EC P-256 private key, asymmetric YubiHSM 2 authentication (firmware 5.6+).
    pub const EC_P256_YUBICO_AUTHENTICATION: u8 = 39;
}

/// Management key length (yubikit `MANAGEMENT_KEY_LEN`).
pub const MANAGEMENT_KEY_LEN: usize = 16;
/// Credential password length (yubikit `CREDENTIAL_PASSWORD_LEN`).
pub const CREDENTIAL_PASSWORD_LEN: usize = 16;
/// Shortest label in bytes (yubikit `MIN_LABEL_LEN`).
pub const MIN_LABEL_LEN: usize = 1;
/// Longest label in bytes (yubikit `MAX_LABEL_LEN`).
pub const MAX_LABEL_LEN: usize = 64;
/// Tries for the management key and for each credential password (yubikit
/// `INITIAL_RETRY_COUNTER`).
pub const RETRIES: u8 = 8;
/// Factory management key: sixteen zero bytes (yubikit `DEFAULT_MANAGEMENT_KEY`).
pub const DEFAULT_MANAGEMENT_KEY: [u8; MANAGEMENT_KEY_LEN] = [0; MANAGEMENT_KEY_LEN];
/// Credential slots (YESDK `AddCredentialCommand`: "The application can store up to 32
/// credentials, and each credential must have a unique label").
pub const MAX_CREDENTIALS: usize = 32;
/// How long a touch-required CALCULATE waits for the user.
///
/// Model value: no public source gives the hsmauth timeout; 15 s is the touch timeout
/// YubiKeys use for other CCID applications.
pub const TOUCH_TIMEOUT_MS: Millis = 15_000;
/// RESET parameters `P1 P2 = DE AD` (yubikit `HsmAuthSession.reset`).
pub const RESET_P1P2: [u8; 2] = [0xDE, 0xAD];
/// Largest chained command this application assembles (ISO/IEC 7816-4 §5.1.1.1).
///
/// Model value: the largest valid command (asymmetric CALCULATE) is about 300 bytes.
pub const MAX_COMMAND_LEN: usize = 2048;

//! CTAP status codes (CTAP 2.1 §8.2 "Status codes") and command codes (CTAP 2.1 §8.1
//! "Command Codes", §6).
//!
//! A CTAP2 response is one status byte followed by the CBOR response map, if any
//! (CTAP 2.1 §8). Only the codes this crate answers are listed.

/// `CTAP1_ERR_SUCCESS` / `CTAP2_OK`.
pub const OK: u8 = 0x00;
/// `CTAP1_ERR_INVALID_COMMAND`: the command is not a valid CTAP command.
pub const INVALID_COMMAND: u8 = 0x01;
/// `CTAP1_ERR_INVALID_PARAMETER`: the command included an invalid parameter.
pub const INVALID_PARAMETER: u8 = 0x02;
/// `CTAP1_ERR_INVALID_LENGTH`: invalid message or item length.
pub const INVALID_LENGTH: u8 = 0x03;
/// `CTAP1_ERR_INVALID_SEQ`: invalid message sequencing (authenticatorLargeBlobs fragment
/// offset, §6.10.2).
pub const INVALID_SEQ: u8 = 0x04;
/// `CTAP1_ERR_CHANNEL_BUSY`: another operation is in progress.
pub const CHANNEL_BUSY: u8 = 0x06;
/// `CTAP2_ERR_CBOR_UNEXPECTED_TYPE`: invalid or unexpected CBOR type.
pub const CBOR_UNEXPECTED_TYPE: u8 = 0x11;
/// `CTAP2_ERR_INVALID_CBOR`: error when parsing CBOR.
pub const INVALID_CBOR: u8 = 0x12;
/// `CTAP2_ERR_MISSING_PARAMETER`: a required parameter is missing.
pub const MISSING_PARAMETER: u8 = 0x14;
/// `CTAP2_ERR_LIMIT_EXCEEDED`: a limit for the number of items was exceeded.
pub const LIMIT_EXCEEDED: u8 = 0x15;
/// `CTAP2_ERR_LARGE_BLOB_STORAGE_FULL`: the serialized large-blob array would exceed
/// `maxSerializedLargeBlobArray` (§6.10.2).
pub const LARGE_BLOB_STORAGE_FULL: u8 = 0x18;
/// `CTAP2_ERR_CREDENTIAL_EXCLUDED`: a credential in the exclude list is present.
pub const CREDENTIAL_EXCLUDED: u8 = 0x19;
/// `CTAP2_ERR_UNSUPPORTED_ALGORITHM`: none of the requested algorithms is supported.
pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;
/// `CTAP2_ERR_OPERATION_DENIED`: not authorized for the requested operation.
pub const OPERATION_DENIED: u8 = 0x27;
/// `CTAP2_ERR_KEY_STORE_FULL`: internal key storage is full.
pub const KEY_STORE_FULL: u8 = 0x28;
/// `CTAP2_ERR_UNSUPPORTED_OPTION`: unsupported option.
pub const UNSUPPORTED_OPTION: u8 = 0x2B;
/// `CTAP2_ERR_INVALID_OPTION`: not a valid option for the current operation.
pub const INVALID_OPTION: u8 = 0x2C;
/// `CTAP2_ERR_KEEPALIVE_CANCEL`: pending keep-alive was cancelled.
pub const KEEPALIVE_CANCEL: u8 = 0x2D;
/// `CTAP2_ERR_NO_CREDENTIALS`: no valid credentials provided.
pub const NO_CREDENTIALS: u8 = 0x2E;
/// `CTAP2_ERR_USER_ACTION_TIMEOUT`: a user action timeout occurred.
pub const USER_ACTION_TIMEOUT: u8 = 0x2F;
/// `CTAP2_ERR_NOT_ALLOWED`: continuation command not allowed, or reset outside its window.
pub const NOT_ALLOWED: u8 = 0x30;
/// `CTAP2_ERR_PIN_INVALID`.
pub const PIN_INVALID: u8 = 0x31;
/// `CTAP2_ERR_PIN_BLOCKED`: the PIN retry counter reached zero.
pub const PIN_BLOCKED: u8 = 0x32;
/// `CTAP2_ERR_PIN_AUTH_INVALID`: pinUvAuthParam verification failed.
pub const PIN_AUTH_INVALID: u8 = 0x33;
/// `CTAP2_ERR_PIN_AUTH_BLOCKED`: three consecutive PIN mismatches; a power cycle is needed
/// before the next PIN attempt (§6.5.5).
pub const PIN_AUTH_BLOCKED: u8 = 0x34;
/// `CTAP2_ERR_PIN_NOT_SET`.
pub const PIN_NOT_SET: u8 = 0x35;
/// `CTAP2_ERR_PUAT_REQUIRED`: a pinUvAuthToken is required for the selected operation.
pub const PUAT_REQUIRED: u8 = 0x36;
/// `CTAP2_ERR_PIN_POLICY_VIOLATION`: the PIN or minimum PIN length violates policy.
pub const PIN_POLICY_VIOLATION: u8 = 0x37;
/// `CTAP2_ERR_INTEGRITY_FAILURE`: the large-blob array failed its integrity check (§6.10.2).
pub const INTEGRITY_FAILURE: u8 = 0x3D;
/// `CTAP2_ERR_INVALID_SUBCOMMAND`: the subcommand is not valid or not supported.
pub const INVALID_SUBCOMMAND: u8 = 0x3E;
/// `CTAP2_ERR_UNAUTHORIZED_PERMISSION`: a requested permission is not supported (§6.5.5.7).
pub const UNAUTHORIZED_PERMISSION: u8 = 0x40;
/// `CTAP1_ERR_OTHER`: other unspecified error. Used for storage failures
/// (`docs/CONTRACTS.md`, persisted state rules).
pub const OTHER: u8 = 0x7F;

/// Command codes (CTAP 2.1 §8.1).
pub mod command {
    /// `authenticatorMakeCredential` (§6.1).
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    /// `authenticatorGetAssertion` (§6.2).
    pub const GET_ASSERTION: u8 = 0x02;
    /// `authenticatorGetInfo` (§6.4).
    pub const GET_INFO: u8 = 0x04;
    /// `authenticatorClientPIN` (§6.5).
    pub const CLIENT_PIN: u8 = 0x06;
    /// `authenticatorReset` (§6.6).
    pub const RESET: u8 = 0x07;
    /// `authenticatorGetNextAssertion` (§6.3).
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    /// `authenticatorCredentialManagement` (§6.8).
    pub const CREDENTIAL_MANAGEMENT: u8 = 0x0A;
    /// `authenticatorSelection` (§6.9).
    pub const SELECTION: u8 = 0x0B;
    /// `authenticatorLargeBlobs` (§6.10).
    pub const LARGE_BLOBS: u8 = 0x0C;
    /// `authenticatorConfig` (§6.11).
    pub const CONFIG: u8 = 0x0D;
    /// `authenticatorCredentialManagement` prototype (`credentialMgmtPreview`, FIDO_2_1_PRE).
    pub const CREDENTIAL_MANAGEMENT_PREVIEW: u8 = 0x41;
}

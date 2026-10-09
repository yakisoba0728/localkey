//! FIDO authenticator: CTAP 2.1 (makeCredential, getAssertion, getNextAssertion, getInfo,
//! clientPIN with PIN/UV auth protocols 1 and 2, reset, credentialManagement,
//! largeBlobs, authenticatorConfig, selection) and U2F raw messages (CTAP1).
//! Extensions: credProtect, hmac-secret, credBlob, largeBlobKey, minPinLength.

#![forbid(unsafe_code)]

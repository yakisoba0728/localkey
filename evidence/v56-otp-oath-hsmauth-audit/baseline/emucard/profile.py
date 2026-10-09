"""Public USB CCID limits observed on the firmware 5.7.4 reference device.

Electrical values describe its USB class profile; software has no physical clock.
The card ATR, keys and attestation identity remain independent.
"""

CCID_MESSAGE_LENGTH = 3072
CCID_PAYLOAD_LENGTH = CCID_MESSAGE_LENGTH - 10
CCID_CLOCK_KHZ = 4000
CCID_DATA_RATE = 307200
MAX_COMMAND_APDU_LENGTH = 65544
MAX_RESPONSE_APDU_LENGTH = 65538

# Published Yubico PIV limits, separate from the ISO/CCID transport envelope.
# This model budgets assembled plaintext APDU data and stored object values.
# Firmware header/allocation overhead has not been measured on the reference.
PIV_APDU_DATA_LENGTH = 3072
PIV_OBJECT_STORAGE_LENGTH = 51200

# Public OpenPGP capability bytes read through the native system PC/SC reader.
# Storage/rejection boundaries are modeled from these declared ceilings; no PIN
# or write was attempted on the reference. Header/SCP allocation is unmeasured.
OPENPGP_CHALLENGE_LENGTH = 3070
OPENPGP_CERTIFICATE_LENGTH = 2048
OPENPGP_SPECIAL_DO_LENGTH = 255
OPENPGP_EXTENDED_CAPABILITIES = bytes.fromhex("7d000bfe080000ff0000")
OPENPGP_HISTORICAL_BYTES = bytes.fromhex("00730000e0059000")
OPENPGP_EXTENDED_LENGTH_INFO = bytes.fromhex("02020bfe02020bfe")
OPENPGP_GENERAL_FEATURE_MANAGEMENT = bytes.fromhex("810120")
OPENPGP_DEFAULT_RSA_ATTRIBUTES = bytes.fromhex("010800001100")

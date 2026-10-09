// authenticatorClientPIN (0x06), PIN protocol 2 only (DESIGN.md "PIN protocol 2").
#include "pin_state.hpp"

#include "ctap_internal.hpp"
#include "swpasskey/log/log.hpp"
#include "swpasskey/text.hpp"

#include <openssl/crypto.h>

#include <cstring>
#include <algorithm>

namespace swpk::ctap::detail {

using cbor::Reader;
using cbor::Writer;

namespace {

constexpr std::uint8_t kSubGetRetries = 0x01;
constexpr std::uint8_t kSubGetKeyAgreement = 0x02;
constexpr std::uint8_t kSubSetPin = 0x03;
constexpr std::uint8_t kSubChangePin = 0x04;
constexpr std::uint8_t kSubGetPinToken = 0x05;
constexpr std::uint8_t kSubGetTokenUsingUv = 0x06;
constexpr std::uint8_t kSubGetUvRetries = 0x07;
constexpr std::uint8_t kSubGetTokenUsingPin = 0x09;

constexpr std::uint8_t kSupportedPerms = kPermMc | kPermGa | kPermCm | kPermLbw | kPermAcfg;

std::span<const std::uint8_t> bytes_of(const char* s) {
  return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s), std::strlen(s));
}

std::vector<std::uint8_t> encode_cose_ecdh(const crypto::P256PublicKey& pub) {
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_int(1), Writer::encode_int(2));     // kty EC2
  m.emplace_back(Writer::encode_int(3), Writer::encode_int(-25));   // alg ECDH-ES+HKDF-256
  m.emplace_back(Writer::encode_int(-1), Writer::encode_int(1));    // crv P-256
  m.emplace_back(Writer::encode_int(-2), Writer::encode_bstr(pub.x));
  m.emplace_back(Writer::encode_int(-3), Writer::encode_bstr(pub.y));
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

}  // namespace

SharedSecret::~SharedSecret() {
  OPENSSL_cleanse(hmac_key.data(), hmac_key.size());
  OPENSSL_cleanse(aes_key.data(), aes_key.size());
}

Result<SharedSecret> derive_shared_secret(crypto::Provider& p, std::span<const std::uint8_t, 32> z) {
  const std::uint8_t salt[32] = {};
  SharedSecret ss;
  auto h = p.hkdf_sha256(z, salt, bytes_of("CTAP2 HMAC key"));
  auto a = p.hkdf_sha256(z, salt, bytes_of("CTAP2 AES key"));
  if (!h || !a) {
    return std::unexpected(Status::Other);
  }
  ss.hmac_key = *h;
  ss.aes_key = *a;
  OPENSSL_cleanse(h->data(), h->size());
  OPENSSL_cleanse(a->data(), a->size());
  return ss;
}

Result<std::vector<std::uint8_t>> pin2_encrypt(crypto::Provider& p, const SharedSecret& ss,
                                               std::span<const std::uint8_t> pt) {
  std::array<std::uint8_t, 16> iv{};
  if (ss.protocol == 2 && !p.random(iv)) {
    return std::unexpected(Status::Other);
  }
  auto ct = p.aes256cbc_encrypt(ss.aes_key, iv, pt);
  if (!ct) {
    return std::unexpected(ct.error());
  }
  std::vector<std::uint8_t> out;
  if (ss.protocol == 2) out.assign(iv.begin(), iv.end());
  out.insert(out.end(), ct->begin(), ct->end());
  return out;
}

Result<std::vector<std::uint8_t>> pin2_decrypt(crypto::Provider& p, const SharedSecret& ss,
                                               std::span<const std::uint8_t> ct) {
  if (ct.size() < (ss.protocol == 2 ? 32U : 16U) || ct.size() % 16 != 0) {
    return std::unexpected(Status::InvalidParameter);
  }
  std::array<std::uint8_t, 16> iv{};
  if (ss.protocol == 2) std::memcpy(iv.data(), ct.data(), 16);
  return p.aes256cbc_decrypt(ss.aes_key, iv, ct.subspan(ss.protocol == 2 ? 16 : 0));
}

Result<std::array<std::uint8_t, 32>> pin2_authenticate(crypto::Provider& p,
                                                       std::span<const std::uint8_t> key,
                                                       std::span<const std::uint8_t> msg) {
  return p.hmac_sha256(key, msg);
}

PinManager::PinManager(crypto::Provider& crypto, store::CredentialStore& store,
                       std::chrono::milliseconds token_idle_timeout)
    : crypto_(crypto),
      store_(store),
      token_idle_timeout_(token_idle_timeout) {
  (void)regenerate_key_agreement();
}

PinManager::~PinManager() { invalidate_token(); }

bool PinManager::pin_set() const { return store_.pin().hash.has_value(); }

Result<void> PinManager::set_pin_local(std::string_view pin) {
  auto cp_count = utf8_code_points(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(pin.data()), pin.size()));
  if (!cp_count) return std::unexpected(Status::PinPolicyViolation);
  const auto cps = *cp_count;
  if (pin.empty() || cps < store_.pin().min_length || cps > 63 || pin.size() > 63 || pin.find(char{0}) != std::string_view::npos) {
    return std::unexpected(Status::PinPolicyViolation);
  }
  const auto digest = crypto_.sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(pin.data()), pin.size()));
  auto st = store_.pin();
  st.force_change = false;
  st.length = static_cast<std::uint8_t>(cps);
  st.hash = std::array<std::uint8_t, 16>{};
  std::memcpy(st.hash->data(), digest.data(), 16);
  st.retries = kMaxRetries;
  if (auto r = store_.set_pin(st); !r) {
    return std::unexpected(Status::Other);
  }
  consecutive_failures_ = 0;
  invalidate_token();
  log::info("pin_set_local");
  return {};
}

std::uint8_t PinManager::retries() const { return store_.pin().retries; }

void PinManager::invalidate_token() {
  if (token_) {
    OPENSSL_cleanse(token_->bytes.data(), token_->bytes.size());
    token_.reset();
  }
}

Result<void> PinManager::regenerate_key_agreement() {
  invalidate_token();
  auto k = crypto_.generate_p256_ephemeral();
  if (!k) {
    return std::unexpected(k.error());
  }
  ka_ = std::move(*k);
  return {};
}

Result<SharedSecret> PinManager::shared_secret_for(const crypto::P256PublicKey& platform_key, std::uint64_t protocol) {
  if (!ka_) {
    return std::unexpected(Status::Other);
  }
  auto z = ka_->shared_secret_x(platform_key);
  if (!z) {
    return std::unexpected(Status::InvalidParameter);
  }
  Result<SharedSecret> ss;
  if (protocol == 1) {
    SharedSecret v; v.protocol = 1; v.aes_key = crypto_.sha256(*z); v.hmac_key = v.aes_key; ss = v;
  } else if (protocol == 2) ss = derive_shared_secret(crypto_, *z);
  else ss = std::unexpected(Status::InvalidParameter);
  OPENSSL_cleanse(z->data(), z->size());
  return ss;
}

Result<std::vector<std::uint8_t>> PinManager::get_retries() {
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_uint(3), Writer::encode_uint(retries()));
  if (consecutive_failures_ >= 3 && retries() != 0) {
    m.emplace_back(Writer::encode_uint(4), Writer::encode_bool(true));
  }
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

Result<std::vector<std::uint8_t>> PinManager::get_key_agreement() {
  if (!ka_) {
    return std::unexpected(Status::Other);
  }
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_uint(1), encode_cose_ecdh(ka_->pub()));
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

Result<std::array<std::uint8_t, 16>> PinManager::pin_from_padded(
    const SharedSecret& ss, std::span<const std::uint8_t> new_pin_enc) {
  auto padded = pin2_decrypt(crypto_, ss, new_pin_enc);
  if (!padded) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  if (padded->size() < 64) {
    OPENSSL_cleanse(padded->data(), padded->size());
    return std::unexpected(Status::PinPolicyViolation);
  }
  std::size_t len = 0;
  while (len < padded->size() && (*padded)[len] != 0) {
    ++len;
  }
  // Count UTF-8 code points for the 4..63 policy.
  const auto cp_count = utf8_code_points(std::span<const std::uint8_t>(*padded).first(len));
  if (!cp_count) { OPENSSL_cleanse(padded->data(), padded->size()); return std::unexpected(Status::PinPolicyViolation); }
  const auto cps = *cp_count;
  const bool valid_padding = std::all_of(padded->begin() + static_cast<long>(len), padded->end(), [](auto b) { return b == 0; });
  if (len == 0 || cps < store_.pin().min_length || cps > 63 || len > 63 || !valid_padding) {
    OPENSSL_cleanse(padded->data(), padded->size());
    return std::unexpected(Status::PinPolicyViolation);
  }
  new_pin_length_ = static_cast<std::uint8_t>(cps);
  const auto digest = crypto_.sha256(std::span<const std::uint8_t>(padded->data(), len));
  OPENSSL_cleanse(padded->data(), padded->size());
  std::array<std::uint8_t, 16> out{};
  std::memcpy(out.data(), digest.data(), 16);
  return out;
}

Result<void> PinManager::check_pin_hash(const SharedSecret& ss,
                                        std::span<const std::uint8_t> pin_hash_enc,
                                        CancelToken& cancel) {
  auto pin = store_.pin();
  if (!pin.hash) {
    return std::unexpected(Status::PinNotSet);
  }
  if (pin.retries == 0) {
    ++pin_block_;
    return std::unexpected(Status::PinBlocked);
  }
  // CTAP 2.1 requires a power cycle after three consecutive mismatches.
  // Reject without consuming another durable retry, including a correct PIN.
  if (consecutive_failures_ >= 3) return std::unexpected(Status::PinAuthBlocked);
  if (cancel.is_cancelled()) return std::unexpected(Status::KeepaliveCancel);
  // CTAP 2.1 §6.5.5.7 decrements before decrypting pinHashEnc. A malformed
  // encrypted proof therefore consumes a retry just like a mismatched hash.
  pin.retries = static_cast<std::uint8_t>(pin.retries - 1);
  if (auto w = store_.set_pin(pin); !w) {
    log::error("pin_retry_persist_failed");
    return std::unexpected(Status::Other);  // fail closed: no verification without durable retries
  }
  auto got = pin2_decrypt(crypto_, ss, pin_hash_enc);
  const bool ok = got && got->size() == pin.hash->size() &&
                  crypto_.consttime_equal(*got, *pin.hash);
  if (got) OPENSSL_cleanse(got->data(), got->size());
  if (!ok) {
    ++pin_fail_;
    ++consecutive_failures_;
    (void)regenerate_key_agreement();  // spec: new key agreement after a failure
    log::warn("pin_invalid", {{"retries", std::to_string(pin.retries)}});
    if (pin.retries == 0) {
      ++pin_block_;
      return std::unexpected(Status::PinBlocked);
    }
    if (consecutive_failures_ >= 3) return std::unexpected(Status::PinAuthBlocked);
    return std::unexpected(Status::PinInvalid);
  }
  consecutive_failures_ = 0;
  if (pin.retries != kMaxRetries) {
    pin.retries = kMaxRetries;
    (void)store_.set_pin(pin);
  }
  return {};
}

Result<std::vector<std::uint8_t>> PinManager::set_pin(const crypto::P256PublicKey& platform_key,
                                                      std::span<const std::uint8_t> new_pin_enc,
                                                      std::span<const std::uint8_t> pin_auth,
                                                      CancelToken& cancel) {
  (void)cancel;
  if (pin_set()) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  auto ss = shared_secret_for(platform_key, request_protocol_);
  if (!ss) {
    return std::unexpected(ss.error());
  }
  auto mac = pin2_authenticate(crypto_, ss->hmac_key, new_pin_enc);
  if (!mac || !crypto_.consttime_equal(std::span<const std::uint8_t>(*mac).first(ss->protocol == 1 ? 16 : 32), pin_auth)) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  auto hash = pin_from_padded(*ss, new_pin_enc);
  if (!hash) {
    return std::unexpected(hash.error());
  }
  auto st = store_.pin();
  st.force_change = false;
  st.length = new_pin_length_;
  st.hash = *hash;
  st.retries = kMaxRetries;
  if (auto r = store_.set_pin(st); !r) {
    return std::unexpected(Status::Other);
  }
  OPENSSL_cleanse(hash->data(), hash->size());
  consecutive_failures_ = 0;
  log::info("pin_set");
  return std::vector<std::uint8_t>{};
}

Result<std::vector<std::uint8_t>> PinManager::change_pin(
    const crypto::P256PublicKey& platform_key, std::span<const std::uint8_t> pin_hash_enc,
    std::span<const std::uint8_t> new_pin_enc, std::span<const std::uint8_t> pin_auth,
    CancelToken& cancel) {
  auto ss = shared_secret_for(platform_key, request_protocol_);
  if (!ss) {
    return std::unexpected(ss.error());
  }
  std::vector<std::uint8_t> msg(new_pin_enc.begin(), new_pin_enc.end());
  msg.insert(msg.end(), pin_hash_enc.begin(), pin_hash_enc.end());
  auto mac = pin2_authenticate(crypto_, ss->hmac_key, msg);
  if (!mac || !crypto_.consttime_equal(std::span<const std::uint8_t>(*mac).first(ss->protocol == 1 ? 16 : 32), pin_auth)) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  if (auto c = check_pin_hash(*ss, pin_hash_enc, cancel); !c) {
    return std::unexpected(c.error());
  }
  auto hash = pin_from_padded(*ss, new_pin_enc);
  if (!hash) {
    return std::unexpected(hash.error());
  }
  auto st = store_.pin();
  st.force_change = false;
  st.length = new_pin_length_;
  st.hash = *hash;
  st.retries = kMaxRetries;
  if (auto r = store_.set_pin(st); !r) {
    return std::unexpected(Status::Other);
  }
  OPENSSL_cleanse(hash->data(), hash->size());
  invalidate_token();  // K23: PIN change invalidates outstanding tokens
  log::info("pin_changed");
  return std::vector<std::uint8_t>{};
}

Result<std::vector<std::uint8_t>> PinManager::get_token(const crypto::P256PublicKey& platform_key,
                                                        std::span<const std::uint8_t> pin_hash_enc,
                                                        std::uint8_t permissions,
                                                        std::optional<std::string> rp_id,
                                                        bool legacy,
                                                        CancelToken& cancel) {
  auto ss = shared_secret_for(platform_key, request_protocol_);
  if (!ss) {
    return std::unexpected(ss.error());
  }
  if (auto c = check_pin_hash(*ss, pin_hash_enc, cancel); !c) {
    return std::unexpected(c.error());
  }
  // CTAP verifies the old PIN (including durable retry accounting) before
  // reporting a forced change. The superseded 0x05 path uses PIN_INVALID.
  if (store_.pin().force_change) {
    return std::unexpected(legacy ? Status::PinInvalid : Status::PinPolicyViolation);
  }
  PinUvAuthToken t;
  if (!crypto_.random(t.bytes)) {
    return std::unexpected(Status::Other);
  }
  t.permissions = permissions;
  t.permissions_rp_id = std::move(rp_id);
  t.expiry = std::chrono::steady_clock::now() + token_idle_timeout_;
  invalidate_token();
  token_ = t;
  OPENSSL_cleanse(t.bytes.data(), t.bytes.size());
  auto enc = pin2_encrypt(crypto_, *ss, token_->bytes);
  if (!enc) {
    invalidate_token();
    return std::unexpected(Status::Other);
  }
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_uint(2), Writer::encode_bstr(*enc));
  Writer w;
  w.write_map(std::move(m));
  log::info("pin_token_issued", {{"perms", std::to_string(permissions)},
                                 {"rp", token_->permissions_rp_id.value_or("")}});
  return w.finish();
}

Result<bool> PinManager::verify(std::span<const std::uint8_t> param, std::uint64_t protocol,
                                std::span<const std::uint8_t> client_data_hash,
                                std::uint8_t permission, const std::string& rp_id) {
  if (protocol != 1 && protocol != 2) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (!token_) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  if (std::chrono::steady_clock::now() > token_->expiry) {
    log::info("pin_token_expired");
    invalidate_token();
    return std::unexpected(Status::PinAuthInvalid);
  }
  auto mac = pin2_authenticate(crypto_, token_->bytes, client_data_hash);
  if (!mac || !crypto_.consttime_equal(std::span<const std::uint8_t>(*mac).first(protocol == 1 ? 16 : 32), param)) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  if ((token_->permissions & permission) == 0) {
    return std::unexpected(Status::UnauthorizedPermission);
  }
  if (token_->permissions_rp_id) {
    if (*token_->permissions_rp_id != rp_id) {
      return std::unexpected(Status::PinAuthInvalid);
    }
  } else {
    token_->permissions_rp_id = rp_id;  // bind on first use (getPinToken 0x05)
  }
  token_->expiry = std::chrono::steady_clock::now() + token_idle_timeout_;  // not one-shot
  return true;
}

Result<bool> PinManager::verify_command(std::span<const std::uint8_t> param,
    std::uint64_t protocol, std::span<const std::uint8_t> message,
    std::uint8_t permission, const std::optional<std::string>& rp_id) {
  if (protocol != 1 && protocol != 2) return std::unexpected(Status::InvalidParameter);
  if (!token_ || std::chrono::steady_clock::now() > token_->expiry) {
    invalidate_token(); return std::unexpected(Status::PinAuthInvalid);
  }
  auto mac = pin2_authenticate(crypto_, token_->bytes, message);
  if (!mac || !crypto_.consttime_equal(std::span<const std::uint8_t>(*mac).first(protocol == 1 ? 16 : 32), param) ||
      (permission != 0 && (token_->permissions & permission) == 0)) return std::unexpected(Status::PinAuthInvalid);
  if ((permission == kPermCm || permission == 0) && token_->permissions_rp_id &&
      (!rp_id || *rp_id != *token_->permissions_rp_id)) return std::unexpected(Status::PinAuthInvalid);
  token_->expiry = std::chrono::steady_clock::now() + token_idle_timeout_;
  return true;
}
Result<std::vector<std::uint8_t>> PinManager::handle(std::span<const std::uint8_t> body,
                                                     CancelToken& cancel) {
  Reader r(body);
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  std::optional<std::uint64_t> protocol;
  std::optional<std::uint64_t> sub;
  std::optional<crypto::P256PublicKey> key_agreement;
  std::optional<std::vector<std::uint8_t>> pin_auth;
  std::optional<std::vector<std::uint8_t>> new_pin_enc;
  std::optional<std::vector<std::uint8_t>> pin_hash_enc;
  std::optional<std::uint64_t> permissions;
  std::optional<std::string> rp_id;
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = read_int_key(r);
    if (!k) {
      return std::unexpected(k.error());
    }
    switch (*k) {
      case 0x01: {
        auto v = r.uint();
        if (!v) return std::unexpected(v.error());
        protocol = *v;
        break;
      }
      case 0x02: {
        auto v = r.uint();
        if (!v) return std::unexpected(v.error());
        sub = *v;
        break;
      }
      case 0x03: {
        auto v = parse_cose_p256(r);
        if (!v) return std::unexpected(v.error());
        key_agreement = *v;
        break;
      }
      case 0x04: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        pin_auth = *v;
        break;
      }
      case 0x05: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        new_pin_enc = *v;
        break;
      }
      case 0x06: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        pin_hash_enc = *v;
        break;
      }
      case 0x09: {
        auto v = r.uint();
        if (!v) return std::unexpected(v.error());
        permissions = *v;
        break;
      }
      case 0x0A: {
        auto v = r.tstr();
        if (!v) return std::unexpected(v.error());
        rp_id = *v;
        break;
      }
      default:
        if (auto s = r.skip(); !s) return std::unexpected(s.error());
        break;
    }
  }
  if (!sub) {
    return std::unexpected(Status::MissingParameter);
  }
  if (*sub == kSubGetRetries) {
    return get_retries();
  }
  if (*sub == kSubGetTokenUsingUv || *sub == kSubGetUvRetries) {
    return std::unexpected(Status::InvalidSubcommand);  // no built-in UV
  }
  if (!protocol) {
    return std::unexpected(Status::MissingParameter);
  }
  if (*protocol != 1 && *protocol != 2) {
    return std::unexpected(Status::InvalidParameter);
  }
  request_protocol_ = *protocol;
  switch (*sub) {
    case kSubGetKeyAgreement:
      return get_key_agreement();
    case kSubSetPin:
      if (!key_agreement || !new_pin_enc || !pin_auth) {
        return std::unexpected(Status::MissingParameter);
      }
      return set_pin(*key_agreement, *new_pin_enc, *pin_auth, cancel);
    case kSubChangePin:
      if (!key_agreement || !new_pin_enc || !pin_hash_enc || !pin_auth) {
        return std::unexpected(Status::MissingParameter);
      }
      return change_pin(*key_agreement, *pin_hash_enc, *new_pin_enc, *pin_auth, cancel);
    case kSubGetPinToken:
      if (!key_agreement || !pin_hash_enc) {
        return std::unexpected(Status::MissingParameter);
      }
      return get_token(*key_agreement, *pin_hash_enc, kPermMc | kPermGa, std::nullopt, true, cancel);
    case kSubGetTokenUsingPin: {
      if (!key_agreement || !pin_hash_enc || !permissions) {
        return std::unexpected(Status::MissingParameter);
      }
      if (*permissions == 0 || *permissions > 0xFF) {
        return std::unexpected(Status::InvalidParameter);
      }
      const auto perms = static_cast<std::uint8_t>(*permissions);
      if ((perms & ~kSupportedPerms) != 0) {
        return std::unexpected(Status::UnauthorizedPermission);
      }
      if ((perms & (kPermMc | kPermGa)) != 0 && !rp_id) {
        return std::unexpected(Status::UnauthorizedPermission);
      }
      return get_token(*key_agreement, *pin_hash_enc, perms, rp_id, false, cancel);
    }
    default:
      return std::unexpected(Status::InvalidSubcommand);
  }
}

}  // namespace swpk::ctap::detail

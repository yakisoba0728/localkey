// Independent software key handles. No manufacturer key/format is reproduced.
#include "swpasskey/ctap/authenticator.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>

namespace swpk::ctap {
namespace {
constexpr std::array<std::uint8_t, 4> kPrefix{'S', 'K', 'E', 1};
constexpr std::size_t kHandleLength = 128, kPayloadLength = 96;
struct SecretGuard {
  std::span<std::uint8_t> data;
  ~SecretGuard() { OPENSSL_cleanse(data.data(), data.size()); }
};
std::span<const std::uint8_t> bytes(std::string_view text) {
  return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}
Result<void> random_secrets(crypto::Provider& crypto, store::Credential& cred,
                           std::span<const std::uint8_t, 32> root) {
  cred.cred_random.clear();
  for (const auto label : {"SKE/nonresident/credRandom/UV/v1", "SKE/nonresident/credRandom/noUV/v1"}) {
    auto secret = crypto.hkdf_sha256(root, cred.wrapped_id, bytes(label));
    if (!secret) return std::unexpected(secret.error());
    cred.cred_random.insert(cred.cred_random.end(), secret->begin(), secret->end());
    OPENSSL_cleanse(secret->data(), secret->size());
  }
  return {};
}
std::vector<std::uint8_t> associated_data(std::span<const std::uint8_t, 32> rp_hash) {
  std::vector<std::uint8_t> aad(kPrefix.begin(), kPrefix.end());
  aad.insert(aad.end(), rp_hash.begin(), rp_hash.end());
  return aad;
}
}  // namespace

Result<void> Authenticator::wrap_nonresident(store::Credential& cred, const crypto::SigningKey& key) {
  if (cred.rk || key.kind() != crypto::BackendKind::Software || cred.cred_blob.size() > 32 || cred.large_blob_key)
    return std::unexpected(Status::InvalidParameter);
  auto compact = key.export_compact_private();
  SecretGuard compact_guard{compact};
  if (compact.size() != (cred.algorithm == -35 ? 48U : 32U)) return std::unexpected(Status::Other);
  auto root = store_.nonresident_key_or_create(crypto_);
  if (!root) return std::unexpected(root.error());
  SecretGuard root_guard{*root};
  auto wrapping = crypto_.hkdf_sha256(*root, kPrefix, bytes("SKE/nonresident/aead/v1"));
  if (!wrapping) return std::unexpected(wrapping.error());
  SecretGuard wrapping_guard{*wrapping};
  std::array<std::uint8_t, kPayloadLength> payload{};
  SecretGuard payload_guard{payload};
  std::array<std::uint8_t, 12> nonce{};
  if (!crypto_.random(payload) || !crypto_.random(nonce)) return std::unexpected(Status::Other);
  payload[0] = static_cast<std::uint8_t>(cred.algorithm == -7 ? 1 : cred.algorithm == -8 ? 2 : 3);
  payload[1] = cred.cred_protect; payload[2] = 0; payload[3] = static_cast<std::uint8_t>(cred.cred_blob.size());
  std::copy(compact.begin(), compact.end(), payload.begin() + 4);
  std::copy(cred.cred_blob.begin(), cred.cred_blob.end(), payload.begin() + 52);
  const auto aad = associated_data(cred.rp_id_hash);
  auto encrypted = crypto_.aes256gcm_encrypt(*wrapping, nonce, aad, payload);
  if (!encrypted) return std::unexpected(encrypted.error());
  cred.wrapped_id.assign(kPrefix.begin(), kPrefix.end());
  cred.wrapped_id.insert(cred.wrapped_id.end(), nonce.begin(), nonce.end());
  cred.wrapped_id.insert(cred.wrapped_id.end(), encrypted->begin(), encrypted->end());
  if (cred.wrapped_id.size() != kHandleLength) return std::unexpected(Status::Other);
  OPENSSL_cleanse(cred.priv.data(), cred.priv.size());
  cred.priv.assign(compact.begin(), compact.end());
  cred.sign_count = store_.nonresident_counter();
  return random_secrets(crypto_, cred, *root);
}

std::optional<store::Credential> Authenticator::resolve_credential(
    std::span<const std::uint8_t, 32> rp_id_hash, std::span<const std::uint8_t> id,
    std::string_view rp_id) {
  if (auto legacy = store_.find(rp_id_hash, id)) return legacy;
  if (id.size() != kHandleLength || !std::equal(kPrefix.begin(), kPrefix.end(), id.begin())) return std::nullopt;
  auto root = store_.nonresident_key();
  if (!root) return std::nullopt;
  SecretGuard root_guard{*root};
  auto wrapping = crypto_.hkdf_sha256(*root, kPrefix, bytes("SKE/nonresident/aead/v1"));
  if (!wrapping) return std::nullopt;
  SecretGuard wrapping_guard{*wrapping};
  std::array<std::uint8_t, 12> nonce{};
  std::copy_n(id.begin() + 4, nonce.size(), nonce.begin());
  const auto aad = associated_data(rp_id_hash);
  auto plain = crypto_.aes256gcm_decrypt(*wrapping, nonce, aad, id.subspan(16));
  if (!plain) return std::nullopt;
  SecretGuard plaintext_guard{*plain};
  if (plain->size() != kPayloadLength || (*plain)[0] < 1 || (*plain)[0] > 3 ||
      (*plain)[1] < 1 || (*plain)[1] > 3 || (*plain)[2] || (*plain)[3] > 32) return std::nullopt;
  store::Credential cred;
  cred.rk = false; cred.algorithm = (*plain)[0] == 1 ? -7 : (*plain)[0] == 2 ? -8 : -35;
  cred.cred_protect = (*plain)[1]; cred.rp_id = rp_id;
  std::copy(rp_id_hash.begin(), rp_id_hash.end(), cred.rp_id_hash.begin());
  cred.wrapped_id.assign(id.begin(), id.end());
  cred.priv.assign(plain->begin() + 4, plain->begin() + 4 + (cred.algorithm == -35 ? 48 : 32));
  cred.cred_blob.assign(plain->begin() + 52, plain->begin() + 52 + (*plain)[3]);
  auto key = crypto::SoftwareKeyBackend::load_compact_private(cred.priv, cred.algorithm);
  if (!key) { OPENSSL_cleanse(cred.priv.data(), cred.priv.size()); return std::nullopt; }
  cred.pub = (*key)->pub(); cred.public_bytes = (*key)->public_bytes();
  cred.sign_count = store_.nonresident_counter();
  if (!random_secrets(crypto_, cred, *root)) {
    OPENSSL_cleanse(cred.priv.data(), cred.priv.size()); return std::nullopt;
  }
  return cred;
}
}  // namespace swpk::ctap

#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/x509.h>

#include <array>
#include <algorithm>
#include <cstring>
#include <memory>

namespace swpk::crypto {
namespace {

struct PkeyDel {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;

class SoftwareSigningKey final : public SigningKey {
public:
  SoftwareSigningKey(Pkey pkey, P256PublicKey pub, std::array<std::uint8_t, 32> scalar)
      : pkey_(std::move(pkey)), pub_(pub), scalar_(scalar) {}

  BackendKind kind() const override { return BackendKind::Software; }

  P256PublicKey pub() const override { return pub_; }

  Result<std::vector<std::uint8_t>> sign_der(
      std::span<const std::uint8_t> message) const override {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
      return std::unexpected(Status::Other);
    }
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey_.get()) != 1) {
      EVP_MD_CTX_free(ctx);
      return std::unexpected(Status::Other);
    }
    std::size_t len = 0;
    if (EVP_DigestSign(ctx, nullptr, &len, message.data(), message.size()) != 1) {
      EVP_MD_CTX_free(ctx);
      return std::unexpected(Status::Other);
    }
    std::vector<std::uint8_t> der(len);
    if (EVP_DigestSign(ctx, der.data(), &len, message.data(), message.size()) != 1) {
      EVP_MD_CTX_free(ctx);
      return std::unexpected(Status::Other);
    }
    EVP_MD_CTX_free(ctx);
    der.resize(len);
    auto norm = Provider::ecdsa_p256_der_normalize_low_s(der);
    if (!norm) {
      return std::unexpected(norm.error());
    }
    return *norm;
  }

  std::vector<std::uint8_t> persist_handle() const override { return {}; }

  std::array<std::uint8_t, 32> export_scalar() const { return scalar_; }
  std::vector<std::uint8_t> export_private() const override {
    return {scalar_.begin(), scalar_.end()};
  }
  std::vector<std::uint8_t> export_compact_private() const override { return export_private(); }

  ~SoftwareSigningKey() override { OPENSSL_cleanse(scalar_.data(), scalar_.size()); }

private:
  Pkey pkey_;
  P256PublicKey pub_{};
  std::array<std::uint8_t, 32> scalar_{};
};

Result<std::array<std::uint8_t, 32>> scalar_from_pkey(EVP_PKEY* pkey) {
  BIGNUM* bn = nullptr;
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn) != 1 || bn == nullptr) {
    return std::unexpected(Status::Other);
  }
  std::array<std::uint8_t, 32> out{};
  const int n = BN_bn2binpad(bn, out.data(), 32);
  BN_clear_free(bn);
  if (n != 32) {
    OPENSSL_cleanse(out.data(), out.size());
    return std::unexpected(Status::Other);
  }
  return out;
}

P256PublicKey pub_from_pkey(EVP_PKEY* pkey) {
  P256PublicKey out;
  std::uint8_t enc[65];
  std::size_t len = sizeof(enc);
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, enc, sizeof(enc),
                                      &len) != 1 ||
      len != 65 || enc[0] != 0x04) {
    return out;
  }
  std::memcpy(out.x.data(), enc + 1, 32);
  std::memcpy(out.y.data(), enc + 33, 32);
  return out;
}

Result<Pkey> pkey_from_scalar_and_pub(std::span<const std::uint8_t, 32> scalar,
                                      const P256PublicKey& pub) {
  EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM* d = BN_bin2bn(scalar.data(), 32, nullptr);
  BIGNUM* x = BN_bin2bn(pub.x.data(), 32, nullptr);
  BIGNUM* y = BN_bin2bn(pub.y.data(), 32, nullptr);
  if (!ec || !d || !x || !y || EC_KEY_set_private_key(ec, d) != 1 ||
      EC_KEY_set_public_key_affine_coordinates(ec, x, y) != 1) {
    BN_clear_free(d);
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec);
    return std::unexpected(Status::Other);
  }
  BN_clear_free(d);
  BN_free(x);
  BN_free(y);
  EVP_PKEY* raw = EVP_PKEY_new();
  if (!raw || EVP_PKEY_assign_EC_KEY(raw, ec) != 1) {
    EVP_PKEY_free(raw);
    EC_KEY_free(ec);
    return std::unexpected(Status::Other);
  }
  return Pkey{raw};
}

// Extended algorithms use PKCS#8 private material in the encrypted store.
class ExtendedSigningKey final : public SigningKey {
public:
  ExtendedSigningKey(Pkey key, int alg) : key_(std::move(key)), alg_(alg) {}
  BackendKind kind() const override { return BackendKind::Software; }
  P256PublicKey pub() const override { return {}; }
  int algorithm() const override { return alg_; }
  std::vector<std::uint8_t> persist_handle() const override { return {}; }
  std::vector<std::uint8_t> public_bytes() const override {
    std::vector<std::uint8_t> out(alg_ == -8 ? 32 : 97);
    std::size_t n = out.size();
    int ok = alg_ == -8
      ? EVP_PKEY_get_raw_public_key(key_.get(), out.data(), &n)
      : EVP_PKEY_get_octet_string_param(key_.get(), OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                       out.data(), out.size(), &n);
    if (alg_ == -35 && (ok != 1 || n != out.size())) {
      EC_KEY* ec = EVP_PKEY_get1_EC_KEY(key_.get());
      n = ec ? EC_POINT_point2oct(EC_KEY_get0_group(ec), EC_KEY_get0_public_key(ec),
          POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), nullptr) : 0;
      EC_KEY_free(ec); ok = n == out.size() ? 1 : 0;
    }
    if (ok != 1 || n != out.size()) return {};
    return out;
  }
  std::vector<std::uint8_t> export_private() const override {
    PKCS8_PRIV_KEY_INFO* info = EVP_PKEY2PKCS8(key_.get());
    if (!info) return {};
    const int n = i2d_PKCS8_PRIV_KEY_INFO(info, nullptr);
    std::vector<std::uint8_t> out(n > 0 ? static_cast<std::size_t>(n) : 0);
    auto* dst = out.data();
    const bool ok = n > 0 && i2d_PKCS8_PRIV_KEY_INFO(info, &dst) == n;
    PKCS8_PRIV_KEY_INFO_free(info);
    if (!ok) return {};
    return out;
  }
  std::vector<std::uint8_t> export_compact_private() const override {
    std::vector<std::uint8_t> out(alg_ == -8 ? 32 : 48);
    if (alg_ == -8) {
      std::size_t size = out.size();
      if (EVP_PKEY_get_raw_private_key(key_.get(), out.data(), &size) == 1 && size == out.size()) return out;
    } else {
      BIGNUM* value = nullptr;
      const bool ok = EVP_PKEY_get_bn_param(key_.get(), OSSL_PKEY_PARAM_PRIV_KEY, &value) == 1 && value &&
                      BN_bn2binpad(value, out.data(), static_cast<int>(out.size())) == static_cast<int>(out.size());
      BN_clear_free(value);
      if (ok) return out;
    }
    OPENSSL_cleanse(out.data(), out.size()); return {};
  }
  Result<std::vector<std::uint8_t>> sign_der(std::span<const std::uint8_t> msg) const override {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, alg_ == -8 ? nullptr : EVP_sha384(),
                                   nullptr, key_.get()) != 1) return std::unexpected(Status::Other);
    std::size_t n = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &n, msg.data(), msg.size()) != 1)
      return std::unexpected(Status::Other);
    std::vector<std::uint8_t> out(n);
    if (EVP_DigestSign(ctx.get(), out.data(), &n, msg.data(), msg.size()) != 1)
      return std::unexpected(Status::Other);
    out.resize(n);
    return out;
  }
private:
  Pkey key_;
  int alg_;
};
}  // namespace

Result<std::unique_ptr<SigningKey>> SoftwareKeyBackend::generate_algorithm(int alg) {
  if (alg == -7) return generate();
  if (alg != -8 && alg != -35) return std::unexpected(Status::UnsupportedAlgorithm);
  EVP_PKEY* key = alg == -8 ? EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")
                          : EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-384");
  if (!key) return std::unexpected(Status::Other);
  return std::make_unique<ExtendedSigningKey>(Pkey{key}, alg);
}
Result<std::unique_ptr<SigningKey>> SoftwareKeyBackend::load_algorithm(
    std::span<const std::uint8_t> handle, const P256PublicKey& pub, int alg,
    std::span<const std::uint8_t> public_data) {
  if (alg == -7) return load(handle, pub);
  if ((alg != -8 && alg != -35) || handle.empty() || handle.size() > 512)
    return std::unexpected(Status::InvalidCredential);
  const auto* ptr = handle.data();
  PKCS8_PRIV_KEY_INFO* info = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &ptr, static_cast<long>(handle.size()));
  if (!info) return std::unexpected(Status::InvalidCredential);
  Pkey key{EVP_PKCS82PKEY(info)};
  PKCS8_PRIV_KEY_INFO_free(info);
  if (!key || ptr != handle.data() + handle.size()) return std::unexpected(Status::InvalidCredential);
  if (alg == -8 && !EVP_PKEY_is_a(key.get(), "ED25519"))
    return std::unexpected(Status::InvalidCredential);
  if (alg == -35) {
    char group[32]{};
    std::size_t n = 0;
    if (!EVP_PKEY_is_a(key.get(), "EC") ||
        EVP_PKEY_get_utf8_string_param(key.get(), OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &n) != 1 ||
        std::string_view(group) != "secp384r1") return std::unexpected(Status::InvalidCredential);
  }
  auto out = std::make_unique<ExtendedSigningKey>(std::move(key), alg);
  const auto bytes = out->public_bytes();
  if (bytes.size() != public_data.size() ||
      CRYPTO_memcmp(bytes.data(), public_data.data(), bytes.size()) != 0)
    return std::unexpected(Status::InvalidCredential);
  return out;
}

Result<std::unique_ptr<SigningKey>> SoftwareKeyBackend::generate() {
  EVP_PKEY* raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
  if (!raw) {
    return std::unexpected(Status::Other);
  }
  auto pub = pub_from_pkey(raw);
  auto sc = scalar_from_pkey(raw);
  if (!sc) {
    EVP_PKEY_free(raw);
    return std::unexpected(sc.error());
  }
  return std::make_unique<SoftwareSigningKey>(Pkey{raw}, pub, *sc);
}

Result<std::unique_ptr<SigningKey>> SoftwareKeyBackend::load(
    std::span<const std::uint8_t> handle, const P256PublicKey& pub) {
  if (handle.size() != 32) {
    return std::unexpected(Status::InvalidParameter);
  }
  std::array<std::uint8_t, 32> sc{};
  std::memcpy(sc.data(), handle.data(), 32);
  auto p = pkey_from_scalar_and_pub(sc, pub);
  if (!p) {
    return std::unexpected(p.error());
  }
  std::array<std::uint8_t, 32> sca{};
  std::memcpy(sca.data(), handle.data(), 32);
  return std::make_unique<SoftwareSigningKey>(std::move(*p), pub, sca);
}

Result<P256PublicKey> p256_pub_from_scalar(std::span<const std::uint8_t, 32> scalar) {
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM* d = BN_bin2bn(scalar.data(), 32, nullptr);
  BN_CTX* ctx = BN_CTX_new();
  EC_POINT* pt = group != nullptr ? EC_POINT_new(group) : nullptr;
  P256PublicKey out{};
  bool ok = group != nullptr && d != nullptr && ctx != nullptr && pt != nullptr &&
            EC_POINT_mul(group, pt, d, nullptr, nullptr, ctx) == 1;
  if (ok) {
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    ok = x != nullptr && y != nullptr &&
         EC_POINT_get_affine_coordinates(group, pt, x, y, ctx) == 1 &&
         BN_bn2binpad(x, out.x.data(), 32) == 32 && BN_bn2binpad(y, out.y.data(), 32) == 32;
    BN_free(x);
    BN_free(y);
  }
  EC_POINT_free(pt);
  BN_CTX_free(ctx);
  BN_clear_free(d);
  EC_GROUP_free(group);
  if (!ok) {
    OPENSSL_cleanse(out.x.data(), out.x.size());
    OPENSSL_cleanse(out.y.data(), out.y.size());
    return std::unexpected(Status::Other);
  }
  return out;
}

Result<std::unique_ptr<SigningKey>> SoftwareKeyBackend::load_from_scalar(
    std::span<const std::uint8_t, 32> scalar) {
  auto pub = p256_pub_from_scalar(scalar);
  if (!pub) {
    return std::unexpected(pub.error());
  }
  return load(scalar, *pub);
}

Result<std::unique_ptr<SigningKey>> SoftwareKeyBackend::load_compact_private(
    std::span<const std::uint8_t> material, int alg) {
  if (alg == -8 && material.size() == 32) {
    Pkey key{EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr, material.data(), material.size())};
    if (!key) return std::unexpected(Status::InvalidCredential);
    return std::make_unique<ExtendedSigningKey>(std::move(key), alg);
  }
  if ((alg != -7 && alg != -35) || material.size() != (alg == -7 ? 32U : 48U))
    return std::unexpected(Status::InvalidCredential);
  EC_KEY* ec = EC_KEY_new_by_curve_name(alg == -7 ? NID_X9_62_prime256v1 : NID_secp384r1);
  const EC_GROUP* group = ec ? EC_KEY_get0_group(ec) : nullptr;
  BIGNUM* scalar = BN_bin2bn(material.data(), static_cast<int>(material.size()), nullptr);
  BIGNUM* order = BN_new(); BN_CTX* ctx = BN_CTX_new();
  EC_POINT* point = group ? EC_POINT_new(group) : nullptr;
  const bool valid = ec && scalar && order && ctx && point && !BN_is_zero(scalar) &&
      EC_GROUP_get_order(group, order, ctx) == 1 && BN_cmp(scalar, order) < 0 &&
      EC_POINT_mul(group, point, scalar, nullptr, nullptr, ctx) == 1 &&
      EC_KEY_set_private_key(ec, scalar) == 1 && EC_KEY_set_public_key(ec, point) == 1 && EC_KEY_check_key(ec) == 1;
  BN_clear_free(scalar); BN_free(order); BN_CTX_free(ctx); EC_POINT_free(point);
  if (!valid) { EC_KEY_free(ec); return std::unexpected(Status::InvalidCredential); }
  EVP_PKEY* raw = EVP_PKEY_new();
  if (!raw || EVP_PKEY_assign_EC_KEY(raw, ec) != 1) {
    EVP_PKEY_free(raw); EC_KEY_free(ec); return std::unexpected(Status::Other);
  }
  Pkey key{raw};
  if (alg == -35) return std::make_unique<ExtendedSigningKey>(std::move(key), alg);
  auto public_key = p256_pub_from_scalar(std::span<const std::uint8_t, 32>(material.data(), 32));
  if (!public_key) return std::unexpected(Status::InvalidCredential);
  std::array<std::uint8_t, 32> compact{};
  std::copy(material.begin(), material.end(), compact.begin());
  auto out = std::make_unique<SoftwareSigningKey>(std::move(key), *public_key, compact);
  OPENSSL_cleanse(compact.data(), compact.size()); return out;
}

Result<void> SoftwareKeyBackend::destroy(std::span<const std::uint8_t>) { return {}; }

Result<std::vector<std::uint8_t>> SoftwareKeyBackend::wrap_secret(
    std::span<const std::uint8_t> secret) {
  return std::vector<std::uint8_t>(secret.begin(), secret.end());
}

Result<std::vector<std::uint8_t>> SoftwareKeyBackend::unwrap_secret(
    std::span<const std::uint8_t> wrapped) {
  return std::vector<std::uint8_t>(wrapped.begin(), wrapped.end());
}

Result<std::array<std::uint8_t, 32>> SoftwareKeyBackend::export_scalar_for_store(
    const SigningKey& key) {
  if (key.kind() != BackendKind::Software) {
    return std::unexpected(Status::InvalidParameter);
  }
  return static_cast<const SoftwareSigningKey&>(key).export_scalar();
}

}  // namespace swpk::crypto

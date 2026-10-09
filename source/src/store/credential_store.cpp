#include "swpasskey/store/credential.hpp"

#include "swpasskey/cbor/cbor.hpp"
#include "swpasskey/constants.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/log/log.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>

namespace swpk::store {
namespace {

using cbor::Reader;
using cbor::Writer;
using Entry = std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>;

bool same_id(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
  return a.size() == b.size() && (a.empty() || std::memcmp(a.data(), b.data(), a.size()) == 0);
}

std::vector<std::uint8_t> encode_credential(const Credential& c) {
  std::vector<Entry> m;
  auto put_b = [&](const char* k, std::span<const std::uint8_t> v) {
    m.emplace_back(Writer::encode_tstr(k), Writer::encode_bstr(v));
  };
  auto put_t = [&](const char* k, std::string_view v) {
    m.emplace_back(Writer::encode_tstr(k), Writer::encode_tstr(v));
  };
  auto put_u = [&](const char* k, std::uint64_t v) {
    m.emplace_back(Writer::encode_tstr(k), Writer::encode_uint(v));
  };
  put_t("rp_id", c.rp_id);
  put_b("rp_id_hash", c.rp_id_hash);
  put_t("rp_name", c.rp_name);
  put_b("user_id", c.user_id);
  put_t("user_name", c.user_name);
  put_t("user_display", c.user_display);
  put_b("cred_id", c.cred_id);
  put_u("backend", static_cast<std::uint64_t>(c.backend));
  put_b("handle", c.handle);
  put_b("priv", c.priv);
  put_b("pub_x", c.pub.x);
  put_b("pub_y", c.pub.y);
  put_u("sign_count", c.sign_count);
  put_u("created", c.created_unix);
  put_u("last_used", c.last_used_unix);
  put_b("cred_random", c.cred_random);
  m.emplace_back(Writer::encode_tstr("algorithm"), Writer::encode_int(c.algorithm));
  put_b("public_bytes", c.public_bytes);
  put_u("cred_protect", c.cred_protect);
  put_b("cred_blob", c.cred_blob);
  if (c.large_blob_key) put_b("large_blob_key", *c.large_blob_key);
  m.emplace_back(Writer::encode_tstr("rk"), Writer::encode_bool(c.rk));
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

template <std::size_t N>
Result<void> read_fixed(Reader& r, std::array<std::uint8_t, N>& out) {
  auto b = r.bstr();
  if (!b) {
    return std::unexpected(b.error());
  }
  if (b->size() != N) {
    return std::unexpected(Status::InvalidCbor);
  }
  std::memcpy(out.data(), b->data(), N);
  return {};
}

Result<Credential> decode_credential(Reader& r) {
  Credential c;
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  for (std::size_t i = 0; i < *n; ++i) {
    auto key = r.tstr();
    if (!key) {
      return std::unexpected(key.error());
    }
    const std::string& k = *key;
    Result<void> rc;
    if (k == "rp_id") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      c.rp_id = *v;
    } else if (k == "rp_id_hash") {
      rc = read_fixed(r, c.rp_id_hash);
    } else if (k == "rp_name") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      c.rp_name = *v;
    } else if (k == "user_id") {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      c.user_id = *v;
    } else if (k == "user_name") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      c.user_name = *v;
    } else if (k == "user_display") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      c.user_display = *v;
    } else if (k == "cred_id") {
      rc = read_fixed(r, c.cred_id);
    } else if (k == "backend") {
      auto v = r.uint();
      if (!v) return std::unexpected(v.error());
      if (*v > 2) return std::unexpected(Status::InvalidCbor);
      c.backend = static_cast<crypto::BackendKind>(*v);
    } else if (k == "handle") {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      c.handle = *v;
    } else if (k == "priv") {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      c.priv = *v;
    } else if (k == "pub_x") {
      rc = read_fixed(r, c.pub.x);
    } else if (k == "pub_y") {
      rc = read_fixed(r, c.pub.y);
    } else if (k == "sign_count") {
      auto v = r.uint();
      if (!v) return std::unexpected(v.error());
      c.sign_count = static_cast<std::uint32_t>(*v);
    } else if (k == "created") {
      auto v = r.uint();
      if (!v) return std::unexpected(v.error());
      c.created_unix = *v;
    } else if (k == "last_used") {
      auto v = r.uint();
      if (!v) return std::unexpected(v.error());
      c.last_used_unix = *v;
    } else if (k == "cred_random") {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      c.cred_random = *v;
    } else if (k == "algorithm") {
      auto v = r.integer(); if (!v) return std::unexpected(v.error());
      if (*v != -7 && *v != -8 && *v != -35) return std::unexpected(Status::InvalidCbor);
      c.algorithm = static_cast<int>(*v);
    } else if (k == "public_bytes" || k == "cred_blob") {
      auto v = r.bstr(); if (!v) return std::unexpected(v.error());
      (k == "public_bytes" ? c.public_bytes : c.cred_blob) = std::move(*v);
    } else if (k == "cred_protect") {
      auto v = r.uint(); if (!v || *v < 1 || *v > 3) return std::unexpected(Status::InvalidCbor);
      c.cred_protect = static_cast<std::uint8_t>(*v);
    } else if (k == "large_blob_key") {
      c.large_blob_key.emplace(); rc = read_fixed(r, *c.large_blob_key);
    } else if (k == "rk") {
      auto v = r.boolean();
      if (!v) return std::unexpected(v.error());
      c.rk = *v;
    } else {
      rc = r.skip();
    }
    if (!rc) {
      return std::unexpected(rc.error());
    }
  }
  return c;
}

}  // namespace

Result<void> CredentialStore::validate(const Credential& c) {
  if (!c.wrapped_id.empty()) return std::unexpected(Status::InvalidParameter);
  if (c.rp_id.empty() || c.rp_id.size() > 255) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (c.user_id.size() > 64) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (c.cred_protect < 1 || c.cred_protect > 3 || c.cred_blob.size() > 32)
    return std::unexpected(Status::InvalidParameter);
  if (c.algorithm != -7 && c.algorithm != -8 && c.algorithm != -35)
    return std::unexpected(Status::InvalidParameter);
  if (c.algorithm != -7 && (c.backend != crypto::BackendKind::Software ||
      c.public_bytes.size() != (c.algorithm == -8 ? 32U : 97U)))
    return std::unexpected(Status::InvalidParameter);
  if (c.backend == crypto::BackendKind::Software) {
    if (!c.handle.empty() || (c.algorithm == -7 ? c.priv.size() != 32 : c.priv.empty() || c.priv.size() > 512)) {
      return std::unexpected(Status::InvalidParameter);
    }
  } else {
    if (!c.priv.empty() || c.handle.empty()) {
      return std::unexpected(Status::InvalidParameter);
    }
  }
  return {};
}

std::unique_ptr<CredentialStore> CredentialStore::open_memory() {
  return std::unique_ptr<CredentialStore>(new CredentialStore());
}

Result<std::unique_ptr<CredentialStore>> CredentialStore::open_with(
    std::span<const std::uint8_t> plaintext, std::unique_ptr<Persister> persister) {
  std::unique_ptr<CredentialStore> s(new CredentialStore());
  s->persister_ = std::move(persister);
  if (!plaintext.empty()) {
    std::lock_guard<std::mutex> lk(s->mu_);
    if (auto r = s->load_locked(plaintext); !r) {
      return std::unexpected(r.error());
    }
  }
  return s;
}

Result<void> CredentialStore::load_locked(std::span<const std::uint8_t> plaintext) {
  Reader r(plaintext);
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  for (std::size_t i = 0; i < *n; ++i) {
    auto key = r.tstr();
    if (!key) {
      return std::unexpected(key.error());
    }
    const std::string& k = *key;
    if (k == "aaguid") {
      std::array<std::uint8_t, 16> a{};
      if (auto rc = read_fixed(r, a); !rc) return rc;
    } else if (k == "install_id") {
      if (auto rc = read_fixed(r, install_id_); !rc) return rc;
    } else if (k == "serial") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      serial_ = *v;
    } else if (k == "nonresident_key") {
      nonresident_key_.emplace();
      if (auto rc = read_fixed(r, *nonresident_key_); !rc) return rc;
    } else if (k == "nonresident_counter") {
      auto v = r.uint();
      if (!v || *v > UINT32_MAX) return std::unexpected(Status::InvalidCbor);
      nonresident_counter_ = static_cast<std::uint32_t>(*v);
    } else if (k == "pin") {
      auto pn = r.map();
      if (!pn) return std::unexpected(pn.error());
      for (std::size_t j = 0; j < *pn; ++j) {
        auto pk = r.tstr();
        if (!pk) return std::unexpected(pk.error());
        if (*pk == "hash") {
          std::array<std::uint8_t, 16> h{};
          if (auto rc = read_fixed(r, h); !rc) return rc;
          pin_.hash = h;
        } else if (*pk == "min_length" || *pk == "length") {
          auto v = r.uint(); if (!v || *v > 63) return std::unexpected(Status::InvalidCbor);
          (*pk == "length" ? pin_.length : pin_.min_length) = static_cast<std::uint8_t>(*v);
        } else if (*pk == "force_change" || *pk == "always_uv") {
          auto v = r.boolean(); if (!v) return std::unexpected(v.error());
          (*pk == "force_change" ? pin_.force_change : pin_.always_uv) = *v;
        } else if (*pk == "min_length_rp_ids") {
          auto a = r.array(); if (!a || *a > 8) return std::unexpected(Status::InvalidCbor);
          for (std::size_t z = 0; z < *a; ++z) {
            auto id = r.tstr(); if (!id || id->empty() || id->size() > 255) return std::unexpected(Status::InvalidCbor);
            pin_.min_length_rp_ids.push_back(*id);
          }
        } else if (*pk == "retries") {
          auto v = r.uint();
          if (!v) return std::unexpected(v.error());
          pin_.retries = static_cast<std::uint8_t>(*v);
        } else if (auto rc = r.skip(); !rc) {
          return rc;
        }
      }
    } else if (k == "tpm") {
      auto tn = r.map();
      if (!tn) return std::unexpected(tn.error());
      for (std::size_t j = 0; j < *tn; ++j) {
        auto tk = r.tstr();
        if (!tk) return std::unexpected(tk.error());
        if (*tk == "srk_unique_seed") {
          if (auto rc = read_fixed(r, tpm_.srk_unique_seed); !rc) return rc;
          tpm_.present = true;
        } else if (*tk == "object_auth") {
          if (auto rc = read_fixed(r, tpm_.object_auth); !rc) return rc;
        } else if (auto rc = r.skip(); !rc) {
          return rc;
        }
      }
    } else if (k == "u2f_attest") {
      auto un = r.map();
      if (!un) return std::unexpected(un.error());
      U2fAttestation a;
      for (std::size_t j = 0; j < *un; ++j) {
        auto uk = r.tstr();
        if (!uk) return std::unexpected(uk.error());
        if (*uk == "priv") {
          auto v = r.bstr();
          if (!v) return std::unexpected(v.error());
          a.priv = *v;
        } else if (*uk == "cert_der") {
          auto v = r.bstr();
          if (!v) return std::unexpected(v.error());
          a.cert_der = *v;
        } else if (auto rc = r.skip(); !rc) {
          return rc;
        }
      }
      u2f_ = std::move(a);
    } else if (k == "large_blob_array") {
      auto v = r.bstr(); if (!v || v->size() > 4096) return std::unexpected(Status::InvalidCbor);
      large_blob_array_ = std::move(*v);
    } else if (k == "creds") {
      auto cn = r.array();
      if (!cn) return std::unexpected(cn.error());
      for (std::size_t j = 0; j < *cn; ++j) {
        auto c = decode_credential(r);
        if (!c) return std::unexpected(c.error());
        if (auto v = validate(*c); !v) {
          log::error("store_row_invalid", {{"rp", c->rp_id}});
          return std::unexpected(Status::Other);
        }
        creds_.push_back(std::move(*c));
      }
    } else if (auto rc = r.skip(); !rc) {
      return rc;
    }
  }
  return {};
}

std::vector<std::uint8_t> CredentialStore::serialize_locked() const {
  std::vector<Entry> top;
  top.emplace_back(Writer::encode_tstr("aaguid"), Writer::encode_bstr(kAaguid));
  top.emplace_back(Writer::encode_tstr("install_id"), Writer::encode_bstr(install_id_));
  top.emplace_back(Writer::encode_tstr("serial"), Writer::encode_tstr(serial_));
  top.emplace_back(Writer::encode_tstr("large_blob_array"), Writer::encode_bstr(large_blob_array_));
  if (nonresident_key_) {
    top.emplace_back(Writer::encode_tstr("nonresident_key"), Writer::encode_bstr(*nonresident_key_));
    top.emplace_back(Writer::encode_tstr("nonresident_counter"), Writer::encode_uint(nonresident_counter_));
  }
  {
    std::vector<Entry> pin;
    if (pin_.hash) {
      pin.emplace_back(Writer::encode_tstr("hash"), Writer::encode_bstr(*pin_.hash));
    }
    pin.emplace_back(Writer::encode_tstr("retries"), Writer::encode_uint(pin_.retries));
    pin.emplace_back(Writer::encode_tstr("min_length"), Writer::encode_uint(pin_.min_length));
    pin.emplace_back(Writer::encode_tstr("length"), Writer::encode_uint(pin_.length));
    pin.emplace_back(Writer::encode_tstr("force_change"), Writer::encode_bool(pin_.force_change));
    pin.emplace_back(Writer::encode_tstr("always_uv"), Writer::encode_bool(pin_.always_uv));
    Writer ids; ids.write_array_header(pin_.min_length_rp_ids.size());
    for (const auto& id : pin_.min_length_rp_ids) ids.write_tstr(id);
    pin.emplace_back(Writer::encode_tstr("min_length_rp_ids"), ids.finish());
    Writer w;
    w.write_map(std::move(pin));
    top.emplace_back(Writer::encode_tstr("pin"), w.finish());
  }
  if (tpm_.present) {
    std::vector<Entry> t;
    t.emplace_back(Writer::encode_tstr("srk_unique_seed"),
                   Writer::encode_bstr(tpm_.srk_unique_seed));
    t.emplace_back(Writer::encode_tstr("object_auth"), Writer::encode_bstr(tpm_.object_auth));
    Writer w;
    w.write_map(std::move(t));
    top.emplace_back(Writer::encode_tstr("tpm"), w.finish());
  }
  if (u2f_) {
    std::vector<Entry> u;
    u.emplace_back(Writer::encode_tstr("priv"), Writer::encode_bstr(u2f_->priv));
    u.emplace_back(Writer::encode_tstr("cert_der"), Writer::encode_bstr(u2f_->cert_der));
    Writer w;
    w.write_map(std::move(u));
    top.emplace_back(Writer::encode_tstr("u2f_attest"), w.finish());
  }
  {
    Writer w;
    w.write_array_header(creds_.size());
    for (const auto& c : creds_) {
      w.write_raw(encode_credential(c));
    }
    top.emplace_back(Writer::encode_tstr("creds"), w.finish());
  }
  Writer w;
  w.write_map(std::move(top));
  return w.finish();
}

Result<void> CredentialStore::flush() {
  std::lock_guard<std::mutex> lk(mu_);
  return flush_locked();
}

std::vector<std::uint8_t> CredentialStore::serialize() const {
  std::lock_guard<std::mutex> lk(mu_);
  return serialize_locked();
}

Result<void> CredentialStore::flush_locked() {
  if (!persister_) {
    return {};
  }
  auto pt = serialize_locked();
  auto r = persister_->save(pt);
  OPENSSL_cleanse(pt.data(), pt.size());
  return r;
}

Result<void> CredentialStore::put(Credential c) {
  if (auto v = validate(c); !v) {
    return v;
  }
  std::lock_guard<std::mutex> lk(mu_);
  auto it = std::find_if(creds_.begin(), creds_.end(),
                         [&](const Credential& e) { return e.cred_id == c.cred_id; });
  if (it != creds_.end()) {
    Credential old = *it;
    *it = std::move(c);
    if (auto r = flush_locked(); !r) {
      *it = std::move(old);  // roll back: nothing changed on disk
      return r;
    }
    return {};
  }
  if ((c.rk && std::count_if(creds_.begin(), creds_.end(), [](const auto& e) { return e.rk; }) >= static_cast<long>(kMaxCredentials)) || creds_.size() >= 10000) {
    return std::unexpected(Status::KeyStoreFull);
  }
  creds_.push_back(std::move(c));
  if (auto r = flush_locked(); !r) {
    OPENSSL_cleanse(creds_.back().priv.data(), creds_.back().priv.size());
    creds_.pop_back();
    return r;
  }
  return {};
}

std::vector<Credential> CredentialStore::find_by_rp(
    std::span<const std::uint8_t, 32> rp_id_hash) const {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<Credential> out;
  for (const auto& c : creds_) {
    if (c.rk && same_id(c.rp_id_hash, rp_id_hash)) {
      out.push_back(c);
    }
  }
  return out;
}

std::optional<Credential> CredentialStore::find(std::span<const std::uint8_t, 32> rp_id_hash,
                                                std::span<const std::uint8_t> cred_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& c : creds_) {
    if (same_id(c.rp_id_hash, rp_id_hash) && same_id(c.cred_id, cred_id)) {
      return c;
    }
  }
  return std::nullopt;
}

std::optional<Credential> CredentialStore::find_by_id(std::span<const std::uint8_t> cred_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& c : creds_) {
    if (same_id(c.cred_id, cred_id)) {
      return c;
    }
  }
  return std::nullopt;
}

Result<void> CredentialStore::update_count_and_used(std::span<const std::uint8_t> cred_id,
                                                    std::uint32_t new_count,
                                                    std::uint64_t now_unix) {
  std::lock_guard<std::mutex> lk(mu_);
  for (auto& c : creds_) {
    if (same_id(c.cred_id, cred_id)) {
      const auto old_count = c.sign_count;
      const auto old_used = c.last_used_unix;
      c.sign_count = new_count;
      c.last_used_unix = now_unix;
      if (auto r = flush_locked(); !r) {
        c.sign_count = old_count; c.last_used_unix = old_used; return r;
      }
      return {};
    }
  }
  return std::unexpected(Status::InvalidCredential);
}

Result<void> CredentialStore::erase(std::span<const std::uint8_t> cred_id) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = std::find_if(creds_.begin(), creds_.end(),
                         [&](const Credential& c) { return same_id(c.cred_id, cred_id); });
  if (it == creds_.end()) {
    return std::unexpected(Status::InvalidCredential);
  }
  Credential removed = std::move(*it);
  creds_.erase(it);
  if (auto r = flush_locked(); !r) {
    creds_.push_back(std::move(removed));  // roll back
    return r;
  }
  OPENSSL_cleanse(removed.priv.data(), removed.priv.size());
  return {};
}

std::vector<Credential> CredentialStore::all() const {
  std::lock_guard<std::mutex> lk(mu_);
  return creds_;
}

std::size_t CredentialStore::size() const {
  std::lock_guard<std::mutex> lk(mu_);
  return creds_.size();
}

std::size_t CredentialStore::remaining() const {
  std::lock_guard<std::mutex> lk(mu_);
  return kMaxCredentials - static_cast<std::size_t>(std::count_if(creds_.begin(), creds_.end(), [](const auto& c) { return c.rk; }));
}

std::array<std::size_t, 3> CredentialStore::count_by_backend() const {
  std::lock_guard<std::mutex> lk(mu_);
  std::array<std::size_t, 3> out{};
  for (const auto& c : creds_) {
    ++out[static_cast<std::size_t>(c.backend)];
  }
  return out;
}

Result<void> CredentialStore::factory_reset(
    const std::function<void(const Credential&)>& destroy) {
  std::lock_guard<std::mutex> lk(mu_);
  for (auto& c : creds_) {
    if (destroy) {
      destroy(c);
    }
    OPENSSL_cleanse(c.priv.data(), c.priv.size());
    OPENSSL_cleanse(c.cred_random.data(), c.cred_random.size());
  }
  creds_.clear();
  large_blob_array_.clear();
  if (pin_.hash) {
    OPENSSL_cleanse(pin_.hash->data(), pin_.hash->size());
  }
  pin_ = PinState{};
  OPENSSL_cleanse(tpm_.srk_unique_seed.data(), tpm_.srk_unique_seed.size());
  OPENSSL_cleanse(tpm_.object_auth.data(), tpm_.object_auth.size());
  tpm_ = TpmState{};
  if (u2f_) {
    OPENSSL_cleanse(u2f_->priv.data(), u2f_->priv.size());
  }
  u2f_.reset();
  if (nonresident_key_) OPENSSL_cleanse(nonresident_key_->data(), nonresident_key_->size());
  nonresident_key_.reset(); nonresident_counter_ = 1;
  if (persister_) {
    if (auto r = persister_->reset(); !r) {
      return r;
    }
  }
  return flush_locked();
}

PinState CredentialStore::pin() const {
  std::lock_guard<std::mutex> lk(mu_);
  return pin_;
}

Result<void> CredentialStore::set_pin(PinState state) {
  std::lock_guard<std::mutex> lk(mu_);
  const auto old = pin_;
  pin_ = std::move(state);
  if (auto r = flush_locked(); !r) { pin_ = old; return r; }
  return {};
}

Result<TpmState> CredentialStore::tpm_state_or_create(crypto::Provider& rng) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!tpm_.present) {
    if (!rng.random(tpm_.srk_unique_seed) || !rng.random(tpm_.object_auth)) {
      return std::unexpected(Status::Other);
    }
    tpm_.present = true;
    if (auto r = flush_locked(); !r) {
      return std::unexpected(r.error());
    }
  }
  return tpm_;
}

Result<void> CredentialStore::clear_tpm_state() {
  std::lock_guard<std::mutex> lk(mu_);
  OPENSSL_cleanse(tpm_.srk_unique_seed.data(), tpm_.srk_unique_seed.size());
  OPENSSL_cleanse(tpm_.object_auth.data(), tpm_.object_auth.size());
  tpm_ = TpmState{};
  return flush_locked();
}

std::optional<U2fAttestation> CredentialStore::u2f_attestation() const {
  std::lock_guard<std::mutex> lk(mu_);
  return u2f_;
}

Result<void> CredentialStore::set_u2f_attestation(U2fAttestation a) {
  std::lock_guard<std::mutex> lk(mu_);
  u2f_ = std::move(a);
  return flush_locked();
}

std::string CredentialStore::serial() const {
  std::lock_guard<std::mutex> lk(mu_);
  return serial_;
}

Result<void> CredentialStore::set_serial(std::string serial) {
  std::lock_guard<std::mutex> lk(mu_);
  if (serial_ == serial) {
    return {};
  }
  serial_ = std::move(serial);
  return flush_locked();
}

std::array<std::uint8_t, 16> CredentialStore::install_id() const {
  std::lock_guard<std::mutex> lk(mu_);
  return install_id_;
}

void CredentialStore::set_install_id(std::array<std::uint8_t, 16> id) {
  std::lock_guard<std::mutex> lk(mu_);
  install_id_ = id;
}

Result<void> CredentialStore::put_replacing_user(Credential c) {
  if (!c.rk) return put(std::move(c));
  if (auto v = validate(c); !v) return v;
  std::lock_guard<std::mutex> lk(mu_);
  auto old = creds_;
  std::erase_if(creds_, [&](const auto& e) {
    return e.rk && e.rp_id_hash == c.rp_id_hash && e.user_id == c.user_id;
  });
  if (std::count_if(creds_.begin(), creds_.end(), [](const auto& e) { return e.rk; }) >= static_cast<long>(kMaxCredentials)) {
    creds_ = std::move(old); return std::unexpected(Status::KeyStoreFull);
  }
  creds_.push_back(std::move(c));
  if (auto r = flush_locked(); !r) { creds_ = std::move(old); return r; }
  for (auto& e : old) OPENSSL_cleanse(e.priv.data(), e.priv.size());
  return {};
}
std::vector<std::uint8_t> CredentialStore::large_blob_array() const {
  std::lock_guard<std::mutex> lk(mu_);
  return large_blob_array_;
}
Result<void> CredentialStore::set_large_blob_array(std::vector<std::uint8_t> data) {
  if (data.size() > 4096) return std::unexpected(Status::LargeBlobStorageFull);
  std::lock_guard<std::mutex> lk(mu_);
  auto old = large_blob_array_;
  large_blob_array_ = std::move(data);
  if (auto r = flush_locked(); !r) { large_blob_array_ = std::move(old); return r; }
  return {};
}
Result<std::array<std::uint8_t, 32>> CredentialStore::nonresident_key_or_create(crypto::Provider& rng) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!nonresident_key_) {
    nonresident_key_.emplace();
    if (auto r = rng.random(*nonresident_key_); !r) {
      OPENSSL_cleanse(nonresident_key_->data(), nonresident_key_->size());
      nonresident_key_.reset(); return std::unexpected(r.error());
    }
    if (auto r = flush_locked(); !r) {
      OPENSSL_cleanse(nonresident_key_->data(), nonresident_key_->size());
      nonresident_key_.reset(); return std::unexpected(r.error());
    }
  }
  return *nonresident_key_;
}
std::optional<std::array<std::uint8_t, 32>> CredentialStore::nonresident_key() const {
  std::lock_guard<std::mutex> lk(mu_); return nonresident_key_;
}
std::uint32_t CredentialStore::nonresident_counter() const {
  std::lock_guard<std::mutex> lk(mu_); return nonresident_counter_;
}
Result<void> CredentialStore::advance_nonresident_counter(std::uint32_t expected) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!nonresident_key_ || expected != nonresident_counter_ || expected == UINT32_MAX)
    return std::unexpected(Status::LimitExceeded);
  ++nonresident_counter_;
  if (auto r = flush_locked(); !r) { nonresident_counter_ = expected; return r; }
  return {};
}
}  // namespace swpk::store

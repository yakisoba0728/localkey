// authenticatorMakeCredential (0x01) — DESIGN.md "authenticatorMakeCredential".
#include "ctap_internal.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/log/log.hpp"

#include <openssl/crypto.h>

#include <cstring>
#include <algorithm>
#include <functional>

namespace swpk::ctap {
namespace {

using cbor::Reader;
using cbor::Writer;
using detail::Entry;

struct MakeCredentialRequest {
  std::array<std::uint8_t, 32> client_data_hash{};
  bool have_client_data_hash{false};
  std::optional<detail::RpEntity> rp;
  std::optional<detail::UserEntity> user;
  std::optional<int> algorithm;
  std::vector<detail::PubKeyCredDescriptor> exclude_list;
  detail::ExtensionsIn ext;
  bool have_ext{false};
  detail::Options options;
  std::optional<std::vector<std::uint8_t>> pin_uv_auth_param;
  std::optional<std::uint64_t> pin_uv_auth_protocol;
  std::optional<std::uint64_t> enterprise_attestation;
};

Result<MakeCredentialRequest> parse(std::span<const std::uint8_t> body) {
  MakeCredentialRequest q;
  Reader r(body);
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = detail::read_int_key(r);
    if (!k) {
      return std::unexpected(k.error());
    }
    switch (*k) {
      case 0x01: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        if (v->size() != 32) return std::unexpected(Status::InvalidParameter);
        std::memcpy(q.client_data_hash.data(), v->data(), 32);
        q.have_client_data_hash = true;
        break;
      }
      case 0x02: {
        auto v = detail::parse_rp(r);
        if (!v) return std::unexpected(v.error());
        q.rp = *v;
        break;
      }
      case 0x03: {
        auto v = detail::parse_user(r);
        if (!v) return std::unexpected(v.error());
        q.user = *v;
        break;
      }
      case 0x04: {
        auto v = detail::parse_pub_key_cred_params_algorithm(r);
        if (!v) return std::unexpected(v.error());
        q.algorithm = *v;
        break;
      }
      case 0x05: {
        auto v = detail::parse_descriptor_list(r);
        if (!v) return std::unexpected(v.error());
        q.exclude_list = std::move(*v);
        break;
      }
      case 0x06: {
        auto v = detail::parse_extensions(r);
        if (!v) return std::unexpected(v.error());
        q.ext = *v;
        q.have_ext = true;
        break;
      }
      case 0x07: {
        auto v = detail::parse_options(r);
        if (!v) return std::unexpected(v.error());
        q.options = *v;
        break;
      }
      case 0x08: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        q.pin_uv_auth_param = *v;
        break;
      }
      case 0x09: {
        auto v = r.uint();
        if (!v) return std::unexpected(v.error());
        q.pin_uv_auth_protocol = *v;
        break;
      }
      case 0x0A: {
        // CTAP 2.1 defines enterpriseAttestation as an unsigned integer.
        // Preserve presence, including a value of zero, for the unsupported
        // feature check below.
        auto v = r.uint();
        if (!v) return std::unexpected(v.error());
        q.enterprise_attestation = *v;
        break;
      }
      default:
        if (auto s = r.skip(); !s) return std::unexpected(s.error());
        break;
    }
  }
  if (!q.have_client_data_hash || !q.rp || !q.user || !q.algorithm.has_value()) {
    return std::unexpected(Status::MissingParameter);
  }
  return q;
}

}  // namespace

Result<std::vector<std::uint8_t>> Authenticator::cmd_make_credential(
    std::span<const std::uint8_t> body, CancelToken& cancel) {
  auto fail = [this](Status s) {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    ++metrics_.make_cred_err;
    return std::unexpected(s);
  };

  auto q = parse(body);
  if (!q) {
    return fail(q.error());
  }
  if (q->enterprise_attestation.has_value()) {
    return fail(Status::InvalidParameter);
  }
  if (q->rp->id.empty() || q->rp->id.size() > 255) {
    return fail(Status::InvalidParameter);
  }
  if (q->user->id.size() > 64) {
    return fail(Status::LimitExceeded);
  }
  if (!*q->algorithm) {
    return fail(Status::UnsupportedAlgorithm);
  }
  // Option-byte policy (DESIGN.md).
  if (q->options.up.has_value() && !*q->options.up) {
    return fail(Status::InvalidOption);
  }
  const bool resident = q->options.rk.value_or(false);
  if (q->ext.large_blob_key && !resident) return fail(Status::InvalidOption);
  if (q->options.uv.has_value() && *q->options.uv) {
    return fail(Status::InvalidOption);
  }
  if (q->ext.cred_protect && (*q->ext.cred_protect < 1 || *q->ext.cred_protect > 3))
    return fail(Status::InvalidParameter);

  const auto rp_id_hash = crypto_.sha256(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(q->rp->id.data()),
                                    q->rp->id.size()));

  // PIN / UV (PR9): verify token with `mc` permission when present.
  PinAuthIn pin_in;
  pin_in.param = q->pin_uv_auth_param;
  pin_in.protocol = q->pin_uv_auth_protocol;
  auto uv = check_pin_auth(pin_in, q->client_data_hash, 0x01, q->rp->id, rp_id_hash, true, cancel, !resident);
  if (!uv) {
    return fail(uv.error());
  }

  // excludeList lookup happens before UP but is only reported after it.
  bool excluded = false;
  for (const auto& d : q->exclude_list) {
    if (d.type != "public-key") {
      continue;
    }
    if (resolve_credential(rp_id_hash, d.id, q->rp->id).has_value()) {
      excluded = true;
      break;
    }
  }

  const std::string display = q->user->display_name.empty() ? q->user->name : q->user->display_name;
  const auto decision = confirm_up(ui::PresenceRequest::Kind::MakeCredential, q->rp->id, display,
                                   rp_id_hash, cancel);
  if (decision == ui::Decision::Cancelled) {
    return fail(Status::KeepaliveCancel);
  }
  if (excluded) {
    return fail(Status::CredentialExcluded);  // Allow, Deny and Timeout all land here
  }
  if (decision == ui::Decision::Deny) {
    return fail(Status::OperationDenied);
  }
  if (decision == ui::Decision::Timeout) {
    return fail(Status::UserActionTimeout);
  }
  const auto previous = store_.find_by_rp(rp_id_hash);
  const bool replaces = resident && std::any_of(previous.begin(), previous.end(), [&](const auto& e) { return e.user_id == q->user->id; });
  if (resident && store_.remaining() == 0 && !replaces) {
    return fail(Status::KeyStoreFull);
  }

  // Generate the credential key on the primary backend.
  auto& chosen_backend = *q->algorithm == -7 ? primary_ : software_;
  auto key = chosen_backend.generate_algorithm(*q->algorithm);
  if (!key) {
    log::error("key_generate_failed", {{"backend", primary_backend_name()}});
    return fail(Status::Other);
  }
  store::Credential c;
  c.algorithm = *q->algorithm;
  c.rk = resident;
  c.cred_protect = static_cast<std::uint8_t>(q->ext.cred_protect.value_or(1));
  c.backend = (*key)->kind();
  c.handle = (*key)->persist_handle();
  // Destroy hardware allocations on every failure before the durable commit.
  struct Cleanup { std::function<void()> fn; ~Cleanup() { if (fn) fn(); } };
  Cleanup cleanup{[&] { destroy_key(c); }};
  if (c.algorithm != -7) c.public_bytes = (*key)->public_bytes();
  // The published 5.7 credential-blob profile describes discoverable storage.
  const bool store_blob = resident && q->ext.cred_blob && q->ext.cred_blob->size() <= 32;
  if (store_blob) c.cred_blob = *q->ext.cred_blob;
  if (q->ext.large_blob_key) {
    c.large_blob_key.emplace();
    if (!crypto_.random(*c.large_blob_key)) return fail(Status::Other);
  }
  c.rp_id = q->rp->id;
  c.rp_id_hash = rp_id_hash;
  c.rp_name = q->rp->name;
  c.user_id = q->user->id;
  c.user_name = q->user->name;
  c.user_display = q->user->display_name;
  if (!crypto_.random(c.cred_id)) {
    return fail(Status::Other);
  }
  c.backend = (*key)->kind();
  c.pub = (*key)->pub();
  c.sign_count = 1;
  c.created_unix = now_unix();
  c.last_used_unix = c.created_unix;
  if (c.backend == crypto::BackendKind::Software) {
    c.priv = (*key)->export_private();
    if (c.priv.empty()) return fail(Status::Other);
  }
  // CTAP 2.1 dual credRandom (UV || noUV), generated for every credential.
  if (!resident && c.backend == crypto::BackendKind::Software) {
    if (auto wrapped = wrap_nonresident(c, **key); !wrapped) return fail(wrapped.error());
  } else {
    std::array<std::uint8_t, 64> cred_random{};
    if (!crypto_.random(cred_random)) {
      return fail(Status::Other);
    }
    auto wrapped = chosen_backend.wrap_secret(cred_random);
    OPENSSL_cleanse(cred_random.data(), cred_random.size());
    if (!wrapped) {
      log::error("wrap_secret_failed", {{"backend", primary_backend_name()}});
      return fail(Status::Other);
    }
    c.cred_random = std::move(*wrapped);
  }

  // authData
  std::uint8_t flags = detail::kFlagUp | detail::kFlagAt;
  if (*uv) {
    flags |= detail::kFlagUv;
  }
  std::vector<std::uint8_t> ext_out;
  {
    std::vector<Entry> m;
    if (q->ext.cred_protect) m.emplace_back(Writer::encode_tstr("credProtect"), Writer::encode_uint(c.cred_protect));
    if (q->ext.cred_blob) m.emplace_back(Writer::encode_tstr("credBlob"), Writer::encode_bool(store_blob));
    const auto policy = store_.pin();
    if (q->ext.min_pin_length && std::find(policy.min_length_rp_ids.begin(), policy.min_length_rp_ids.end(), c.rp_id) != policy.min_length_rp_ids.end())
      m.emplace_back(Writer::encode_tstr("minPinLength"), Writer::encode_uint(policy.min_length));
    if (q->ext.hmac_create_secret)
    m.emplace_back(Writer::encode_tstr("hmac-secret"), Writer::encode_bool(true));
    Writer w;
    if (!m.empty()) { w.write_map(std::move(m)); ext_out = w.finish(); }
  }
  if (!ext_out.empty()) {
    flags |= detail::kFlagEd;
  }
  const auto att = detail::build_attested_credential_data(cfg_.aaguid, c);
  const auto auth_data = detail::build_auth_data(rp_id_hash, flags, c.sign_count, att, ext_out);

  // Packed self-attestation: sign(authData || clientDataHash) with the credential key.
  std::vector<std::uint8_t> to_sign(auth_data);
  to_sign.insert(to_sign.end(), q->client_data_hash.begin(), q->client_data_hash.end());
  auto sig = (*key)->sign_der(to_sign);
  if (!sig) {
    log::error("sign_failed", {{"backend", primary_backend_name()}});
    return fail(Status::Other);
  }

  std::vector<Entry> att_stmt;
  att_stmt.emplace_back(Writer::encode_tstr("alg"), Writer::encode_int(c.algorithm));
  att_stmt.emplace_back(Writer::encode_tstr("sig"), Writer::encode_bstr(*sig));
  Writer aw;
  aw.write_map(std::move(att_stmt));

  // Persist only a fully constructed credential. Replacement is one durable transaction.
  if (c.wrapped_id.empty()) {
    if (auto p = store_.put_replacing_user(c); !p) return fail(p.error());
  }
  cleanup.fn = {};
  if (resident) for (const auto& old : previous) if (old.user_id == c.user_id) destroy_key(old);
  std::vector<Entry> resp;
  resp.emplace_back(Writer::encode_uint(1), Writer::encode_tstr("packed"));
  resp.emplace_back(Writer::encode_uint(2), Writer::encode_bstr(auth_data));
  resp.emplace_back(Writer::encode_uint(3), aw.finish());
  if (q->ext.large_blob_key && c.large_blob_key)
    resp.emplace_back(Writer::encode_uint(5), Writer::encode_bstr(*c.large_blob_key));
  Writer w;
  w.write_map(std::move(resp));

  {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    ++metrics_.make_cred_ok;
  }
  log::info("make_credential", {{"rp", c.rp_id}, {"key_backend", primary_backend_name()}});
  return w.finish();
}

}  // namespace swpk::ctap

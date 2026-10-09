// CTAP 2.1 credential management, authenticator configuration, large blobs.
#include "ctap_internal.hpp"
#include "pin_state.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/ctap/profile.hpp"

#include <algorithm>
#include <cstring>
#include <set>

namespace swpk::ctap {
namespace {
using cbor::Reader;
using cbor::Writer;
using detail::Entry;
struct ManagementRequest {
  std::optional<std::uint64_t> sub, protocol;
  std::optional<std::vector<std::uint8_t>> auth;
  std::vector<std::uint8_t> params;
};
Result<ManagementRequest> parse_management(std::span<const std::uint8_t> body) {
  Reader r(body); auto n = r.map(); if (!n) return std::unexpected(n.error());
  ManagementRequest q;
  std::set<std::int64_t> seen;
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = detail::read_int_key(r); if (!k) return std::unexpected(k.error());
    if (!seen.insert(*k).second) return std::unexpected(Status::InvalidCbor);
    if (*k == 1 || *k == 3) {
      auto v = r.uint(); if (!v) return std::unexpected(v.error());
      (*k == 1 ? q.sub : q.protocol) = *v;
    } else if (*k == 2) {
      if (r.peek_major() != 5) return std::unexpected(Status::CborUnexpectedType);
      const auto start = r.offset(); if (auto s = r.skip(); !s) return std::unexpected(s.error());
      q.params.assign(body.begin() + static_cast<long>(start), body.begin() + static_cast<long>(r.offset()));
    } else if (*k == 4) {
      auto v = r.bstr(); if (!v) return std::unexpected(v.error()); q.auth = *v;
    } else if (auto s = r.skip(); !s) return std::unexpected(s.error());
  }
  if (!r.done()) return std::unexpected(Status::InvalidCbor);
  if (!q.sub) return std::unexpected(Status::MissingParameter);
  return q;
}
std::vector<std::uint8_t> encode_rp(const store::Credential& c) {
  Writer w; std::vector<Entry> e;
  e.emplace_back(Writer::encode_tstr("id"), Writer::encode_tstr(c.rp_id));
  if (!c.rp_name.empty()) e.emplace_back(Writer::encode_tstr("name"), Writer::encode_tstr(c.rp_name));
  w.write_map(std::move(e)); return w.finish();
}
std::vector<std::uint8_t> encode_management_row(const store::Credential& c, bool rp,
                                              std::optional<std::size_t> total) {
  Writer w; std::vector<Entry> e;
  if (rp) {
    e.emplace_back(Writer::encode_uint(3), encode_rp(c));
    e.emplace_back(Writer::encode_uint(4), Writer::encode_bstr(c.rp_id_hash));
    if (total) e.emplace_back(Writer::encode_uint(5), Writer::encode_uint(*total));
  } else {
    e.emplace_back(Writer::encode_uint(6), detail::encode_user({c.user_id, c.user_name, c.user_display}, true));
    e.emplace_back(Writer::encode_uint(7), detail::encode_descriptor(c.cred_id));
    e.emplace_back(Writer::encode_uint(8), detail::encode_cose_credential(c));
    if (total) e.emplace_back(Writer::encode_uint(9), Writer::encode_uint(*total));
    e.emplace_back(Writer::encode_uint(10), Writer::encode_uint(c.cred_protect));
    if (c.large_blob_key) e.emplace_back(Writer::encode_uint(11), Writer::encode_bstr(*c.large_blob_key));
  }
  w.write_map(std::move(e)); return w.finish();
}
}  // namespace

Result<std::vector<std::uint8_t>> Authenticator::cmd_credential_management(
    std::span<const std::uint8_t> body, bool preview) {
  auto q = parse_management(body); if (!q) return std::unexpected(q.error());
  const auto sub = *q->sub;
  if (sub == 3 || sub == 5) {
    if (!management_state_ || management_state_->rp != (sub == 3) ||
        management_state_->remaining.empty() || std::chrono::steady_clock::now() > management_state_->expiry) {
      management_state_.reset(); return std::unexpected(Status::NotAllowed);
    }
    const auto c = management_state_->remaining.front();
    management_state_->remaining.erase(management_state_->remaining.begin());
    return encode_management_row(c, sub == 3, std::nullopt);
  }
  management_state_.reset();
  if (sub < 1 || sub > 7) return std::unexpected(Status::InvalidSubcommand);
  if (!q->auth) return std::unexpected(Status::PuattRequired);
  if (!q->protocol) return std::unexpected(Status::MissingParameter);
  std::optional<std::vector<std::uint8_t>> rp_hash;
  std::optional<detail::PubKeyCredDescriptor> descriptor;
  std::optional<detail::UserEntity> user;
  if (!q->params.empty()) {
    Reader r(q->params); auto n = r.map(); if (!n) return std::unexpected(n.error());
    std::set<std::int64_t> seen;
    for (std::size_t i = 0; i < *n; ++i) {
      auto k = detail::read_int_key(r); if (!k) return std::unexpected(k.error());
      if (!seen.insert(*k).second) return std::unexpected(Status::InvalidCbor);
      if (*k == 1) { auto v = r.bstr(); if (!v || v->size() != 32) return std::unexpected(Status::InvalidParameter); rp_hash = *v; }
      else if (*k == 2) { auto v = detail::parse_descriptor(r); if (!v) return std::unexpected(v.error()); descriptor = *v; }
      else if (*k == 3) { auto v = detail::parse_user(r); if (!v) return std::unexpected(v.error()); user = *v; }
      else if (auto s = r.skip(); !s) return std::unexpected(s.error());
    }
  }
  std::vector<std::uint8_t> message{static_cast<std::uint8_t>(sub)};
  message.insert(message.end(), q->params.begin(), q->params.end());
  auto rows = store_.all();
  std::erase_if(rows, [](const auto& c) { return !c.rk; });
  std::optional<std::string> scope;
  std::optional<store::Credential> row;
  if (sub == 4 && rp_hash) for (const auto& c : rows)
    if (std::equal(c.rp_id_hash.begin(), c.rp_id_hash.end(), rp_hash->begin())) { scope = c.rp_id; break; }
  if ((sub == 6 || sub == 7) && descriptor && descriptor->type == "public-key") {
    row = store_.find_by_id(descriptor->id);
    if (row && row->rk) scope = row->rp_id;
  }
  if (auto a = pin_->verify_command(*q->auth, *q->protocol, message, preview ? 0 : detail::kPermCm, scope); !a)
    return std::unexpected(a.error());
  if (sub == 1) {
    Writer w; w.write_map({{Writer::encode_uint(1), Writer::encode_uint(rows.size())},
                           {Writer::encode_uint(2), Writer::encode_uint(store_.remaining())}}); return w.finish();
  }
  if (sub == 2 || sub == 4) {
    if (sub == 2) {
      std::set<std::string> seen;
      std::erase_if(rows, [&](const auto& c) { return !seen.insert(c.rp_id).second; });
    } else {
      if (!rp_hash) return std::unexpected(Status::MissingParameter);
      std::erase_if(rows, [&](const auto& c) { return !std::equal(c.rp_id_hash.begin(), c.rp_id_hash.end(), rp_hash->begin()); });
    }
    if (rows.empty()) return std::unexpected(Status::NoCredentials);
    const auto total = rows.size(); const auto first = rows.front();
    auto st = std::make_unique<detail::ManagementState>();
    st->rp = sub == 2; st->remaining.assign(rows.begin() + 1, rows.end());
    st->expiry = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    management_state_ = std::move(st);
    return encode_management_row(first, sub == 2, total);
  }
  if (!descriptor || (sub == 7 && !user)) return std::unexpected(Status::MissingParameter);
  if (!row || !row->rk) return std::unexpected(Status::NoCredentials);
  if (sub == 6) {
    if (auto d = store_.erase(row->cred_id); !d) return std::unexpected(d.error());
    destroy_key(*row);
  } else {
    if (row->user_id != user->id || user->id.size() > 64) return std::unexpected(Status::InvalidParameter);
    row->user_name = user->name; row->user_display = user->display_name;
    if (auto p = store_.put(*row); !p) return std::unexpected(p.error());
  }
  return std::vector<std::uint8_t>{};
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_authenticator_config(
    std::span<const std::uint8_t> body) {
  auto q = parse_management(body); if (!q) return std::unexpected(q.error());
  if (*q->sub != 2 && *q->sub != 3) return std::unexpected(Status::InvalidParameter);
  auto pin = store_.pin();
  const bool initial_toggle = *q->sub == 2 && !pin.hash && pin.always_uv;
  if (!initial_toggle && (pin.hash || pin.always_uv)) {
    if (!q->auth) return std::unexpected(Status::PuattRequired);
    if (!q->protocol) return std::unexpected(Status::MissingParameter);
    std::vector<std::uint8_t> message(32, 0xff);
    message.push_back(kCmdAuthenticatorConfig); message.push_back(static_cast<std::uint8_t>(*q->sub));
    message.insert(message.end(), q->params.begin(), q->params.end());
    if (auto a = pin_->verify_command(*q->auth, *q->protocol, message, detail::kPermAcfg); !a)
      return std::unexpected(a.error());
  }
  if (*q->sub == 2) pin.always_uv = !pin.always_uv;
  else {
    if (q->params.empty()) return std::unexpected(Status::MissingParameter);
    Reader r(q->params); auto n = r.map(); if (!n) return std::unexpected(n.error());
    std::set<std::int64_t> seen;
    for (std::size_t i = 0; i < *n; ++i) {
      auto k = detail::read_int_key(r); if (!k) return std::unexpected(k.error());
      if (!seen.insert(*k).second) return std::unexpected(Status::InvalidCbor);
      if (*k == 1) {
        auto v = r.uint(); if (!v) return std::unexpected(v.error());
        if (*v < pin.min_length || *v > 63) return std::unexpected(Status::PinPolicyViolation);
        if (pin.hash && (pin.length == 0 ? *v > pin.min_length : *v > pin.length)) pin.force_change = true;
        pin.min_length = static_cast<std::uint8_t>(*v);
      } else if (*k == 2) {
        auto a = r.array(); if (!a) return std::unexpected(a.error());
        if (*a > profile::max_min_pin_rp_ids) return std::unexpected(Status::LimitExceeded);
        // CTAP 2.1 §6.11.4 updates this list only when at least one RP ID is
        // supplied; an empty array leaves the existing allowlist intact.
        if (*a != 0) pin.min_length_rp_ids.clear();
        for (std::size_t j = 0; j < *a; ++j) {
          auto id = r.tstr(); if (!id) return std::unexpected(id.error());
          if (id->empty() || id->size() > 255) return std::unexpected(Status::InvalidParameter);
          pin.min_length_rp_ids.push_back(*id);
        }
      } else if (*k == 3) {
        auto v = r.boolean(); if (!v) return std::unexpected(v.error());
        if (*v && !pin.hash) return std::unexpected(Status::PinNotSet);
        pin.force_change = pin.force_change || *v;
      } else if (auto s = r.skip(); !s) return std::unexpected(s.error());
    }
  }
  if (auto s = store_.set_pin(pin); !s) return std::unexpected(s.error());
  pin_->invalidate_token();
  return std::vector<std::uint8_t>{};
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_large_blobs(
    std::span<const std::uint8_t> body) {
  Reader r(body); auto n = r.map(); if (!n) return std::unexpected(n.error());
  std::optional<std::uint64_t> get, offset, length, protocol;
  std::optional<std::vector<std::uint8_t>> set, auth;
  std::set<std::int64_t> seen;
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = detail::read_int_key(r); if (!k) return std::unexpected(k.error());
    if (!seen.insert(*k).second) return std::unexpected(Status::InvalidCbor);
    if (*k == 1 || *k == 3 || *k == 4 || *k == 6) {
      auto v = r.uint(); if (!v) return std::unexpected(v.error());
      if (*k == 1) get = *v; else if (*k == 3) offset = *v;
      else if (*k == 4) length = *v; else protocol = *v;
    } else if (*k == 2 || *k == 5) {
      auto v = r.bstr(); if (!v) return std::unexpected(v.error()); (*k == 2 ? set : auth) = *v;
    } else if (auto s = r.skip(); !s) return std::unexpected(s.error());
  }
  if (!r.done()) return std::unexpected(Status::InvalidCbor);
  if (!offset || get.has_value() == set.has_value()) return std::unexpected(Status::InvalidParameter);
  if (get) {
    if (length || auth || protocol) return std::unexpected(Status::InvalidParameter);
    if (*get > profile::max_large_blob_fragment) return std::unexpected(Status::InvalidLength);
    auto data = store_.large_blob_array();
    if (data.empty()) {
      data = {0x80}; const auto hash = crypto_.sha256(data); data.insert(data.end(), hash.begin(), hash.begin() + 16);
    }
    if (*offset > data.size()) return std::unexpected(Status::InvalidParameter);
    const auto count = std::min(static_cast<std::size_t>(*get), data.size() - static_cast<std::size_t>(*offset));
    Writer w; w.write_map({{Writer::encode_uint(1), Writer::encode_bstr(std::span<const std::uint8_t>(data).subspan(static_cast<std::size_t>(*offset), count))}}); return w.finish();
  }
  if (set->size() > profile::max_large_blob_fragment) return std::unexpected(Status::InvalidLength);
  if (*offset == 0) {
    if (!length || *length < 17) return std::unexpected(Status::InvalidParameter);
    if (*length > 4096) return std::unexpected(Status::LargeBlobStorageFull);
    // A new write starts a new sequence even if PIN authentication later fails.
    // CTAP 2.1 checks the sequence before verifying pinUvAuthParam.
    large_blob_pending_.clear();
    large_blob_expected_ = static_cast<std::size_t>(*length);
  } else if (length) return std::unexpected(Status::InvalidParameter);
  if (*offset != large_blob_pending_.size() || large_blob_expected_ == 0)
    return std::unexpected(Status::InvalidSeq);
  const auto pin = store_.pin();
  if (pin.hash || pin.always_uv) {
    if (!auth) return std::unexpected(Status::PuattRequired);
    if (!protocol) return std::unexpected(Status::MissingParameter);
    std::vector<std::uint8_t> message(32, 0xff); message.insert(message.end(), {0x0c, 0x00});
    for (unsigned shift = 0; shift < 32; shift += 8) message.push_back(static_cast<std::uint8_t>(*offset >> shift));
    const auto hash = crypto_.sha256(*set); message.insert(message.end(), hash.begin(), hash.end());
    if (auto a = pin_->verify_command(*auth, *protocol, message, detail::kPermLbw); !a) return std::unexpected(a.error());
  }
  if (set->size() > large_blob_expected_ - large_blob_pending_.size()) return std::unexpected(Status::InvalidParameter);
  large_blob_pending_.insert(large_blob_pending_.end(), set->begin(), set->end());
  if (large_blob_pending_.size() == large_blob_expected_) {
    const auto data = std::span<const std::uint8_t>(large_blob_pending_);
    const auto hash = crypto_.sha256(data.first(data.size() - 16));
    if (!crypto_.consttime_equal(std::span<const std::uint8_t>(hash).first(16), data.last(16))) {
      large_blob_pending_.clear(); large_blob_expected_ = 0; return std::unexpected(Status::IntegrityFailure);
    }
    auto saved = store_.set_large_blob_array(large_blob_pending_);
    large_blob_pending_.clear(); large_blob_expected_ = 0;
    if (!saved) return std::unexpected(saved.error());
  }
  return std::vector<std::uint8_t>{};
}
}  // namespace swpk::ctap

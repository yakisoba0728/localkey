#include "swpasskey/ctap/authenticator.hpp"

#include "ctap_internal.hpp"
#include "pin_state.hpp"
#include "swpasskey/ctap/profile.hpp"
#include "swpasskey/log/log.hpp"

#include <chrono>
#include <cstdio>
#include <string>

namespace swpk::ctap {
namespace {

const char* cmd_name(std::uint8_t cmd) {
  switch (cmd) {
    case kCmdMakeCredential:
      return "makeCredential";
    case kCmdGetAssertion:
      return "getAssertion";
    case kCmdGetInfo:
      return "getInfo";
    case kCmdClientPin:
      return "clientPIN";
    case kCmdReset:
      return "reset";
    case kCmdGetNextAssertion:
      return "getNextAssertion";
    case kCmdAuthenticatorSelection:
      return "authenticatorSelection";
    default:
      return "unknown";
  }
}

const char* backend_name(crypto::BackendKind k) {
  switch (k) {
    case crypto::BackendKind::Software:
      return "software";
    case crypto::BackendKind::Tpm2:
      return "tpm2";
    case crypto::BackendKind::SecureEnclave:
      return "se";
  }
  return "software";
}

}  // namespace

Authenticator::Authenticator(AuthenticatorConfig cfg, crypto::Provider& crypto,
                             crypto::KeyBackend& primary_keys, crypto::KeyBackend& software_keys,
                             store::CredentialStore& store, ui::Presence& presence)
    : cfg_(cfg),
      crypto_(crypto),
      primary_(primary_keys),
      software_(software_keys),
      store_(store),
      presence_(presence),
      pin_(std::make_unique<detail::PinManager>(crypto, store, cfg.pin_token_idle_timeout)) {}

Authenticator::~Authenticator() = default;

Result<void> Authenticator::reboot() {
  std::lock_guard guard(op_mu_);
  pin_ = std::make_unique<detail::PinManager>(crypto_, store_, cfg_.pin_token_idle_timeout);
  next_state_.reset(); management_state_.reset();
  large_blob_pending_.clear(); large_blob_expected_ = 0; state_channel_ = 0;
  started_ = std::chrono::steady_clock::now();
  return {};
}

const char* Authenticator::primary_backend_name() const { return backend_name(primary_.kind()); }

AuthenticatorMetrics Authenticator::metrics() const {
  std::lock_guard<std::mutex> lk(metrics_mu_);
  AuthenticatorMetrics m = metrics_;
  m.pin_fail = pin_->pin_fail_count();
  m.pin_block = pin_->pin_block_count();
  return m;
}

void Authenticator::count_status(std::uint8_t status) {
  std::lock_guard<std::mutex> lk(metrics_mu_);
  ++metrics_.ctap_status[status];
}

std::uint64_t Authenticator::now_unix() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

GetInfoSnapshot Authenticator::get_info() const {
  GetInfoSnapshot s;
  s.versions.clear();
  if (cfg_.u2f_enabled) {
    s.versions.emplace_back("U2F_V2");
  }
  s.versions.insert(s.versions.end(), {"FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1"});
  s.extensions = {"credProtect", "hmac-secret", "largeBlobKey", "credBlob", "minPinLength"};
  s.algorithms = {-7, -8, -35};
  s.firmware_version = profile::firmware_revision;
  s.max_msg_size = static_cast<std::uint32_t>(profile::max_message_size);
  s.max_cred_id_len = profile::max_credential_id_length;
  s.options.cred_mgmt = true;
  s.options.large_blobs = true;
  s.options.authnr_cfg = true;
  s.options.set_min_pin_length = true;
  const auto policy = store_.pin();
  s.options.always_uv = policy.always_uv;
  s.options.make_cred_uv_not_rqd = !policy.always_uv;
  s.max_large_blob_array = 4096;
  s.max_cred_blob_length = 32;
  s.min_pin_length = policy.min_length;
  s.max_min_pin_rp_ids = profile::max_min_pin_rp_ids;
  s.force_pin_change = policy.force_change;
  s.aaguid = cfg_.aaguid;
  s.options.client_pin = pin_->pin_set();
  s.options.pin_uv_auth_token = true;
  s.pin_protocols = {2, 1};
  s.remaining_discoverable = static_cast<std::uint32_t>(store_.remaining());
  return s;
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_get_info() {
  return encode_get_info(get_info());
}

ui::Decision Authenticator::confirm_up(ui::PresenceRequest::Kind kind, const std::string& rp_id,
                                       const std::string& user_display,
                                       std::span<const std::uint8_t, 32> rp_id_hash,
                                       CancelToken& cancel) {
  if (cancel.is_cancelled()) {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    ++metrics_.up_cancel;
    return ui::Decision::Cancelled;
  }
  ui::PresenceRequest req;
  req.kind = kind;
  req.rp_id = rp_id;
  req.user_display = user_display;
  std::copy(rp_id_hash.begin(), rp_id_hash.end(), req.rp_id_hash.begin());
  cancel.set_up_needed(true);
  const ui::Decision d = presence_.confirm(req, cancel, cfg_.up_timeout);
  cancel.set_up_needed(false);
  {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    switch (d) {
      case ui::Decision::Allow:
        ++metrics_.up_allow;
        break;
      case ui::Decision::Deny:
        ++metrics_.up_deny;
        break;
      case ui::Decision::Timeout:
        ++metrics_.up_timeout;
        break;
      case ui::Decision::Cancelled:
        ++metrics_.up_cancel;
        break;
    }
  }
  return d;
}

Result<bool> Authenticator::check_pin_auth(const PinAuthIn& in,
                                           std::span<const std::uint8_t, 32> client_data_hash,
                                           std::uint8_t permission, const std::string& rp_id,
                                           std::span<const std::uint8_t, 32> rp_id_hash,
                                           bool is_make, CancelToken& cancel, bool allow_unverified_make) {
  if (!in.param.has_value()) {
    if ((is_make && pin_->pin_set() && !allow_unverified_make) || store_.pin().always_uv) {
      return std::unexpected(Status::PuattRequired);  // makeCredUvNotRqd=false
    }
    return false;  // getAssertion without PIN is allowed (alwaysUv=false): UV=0
  }
  if (!in.protocol.has_value()) {
    return std::unexpected(Status::MissingParameter);
  }
  if (*in.protocol != 1 && *in.protocol != 2) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (in.param->empty()) {
    // CTAP 2.1 §6.1.2 step 1 / §6.2.2 step 1: zero-length param → collect UP,
    // then report whether a PIN is set. Used by platforms to pick a device.
    const auto d = confirm_up(is_make ? ui::PresenceRequest::Kind::MakeCredential
                                      : ui::PresenceRequest::Kind::GetAssertion,
                              rp_id, "", rp_id_hash, cancel);
    if (d == ui::Decision::Cancelled) {
      return std::unexpected(Status::KeepaliveCancel);
    }
    if (d != ui::Decision::Allow) {
      return std::unexpected(Status::OperationDenied);
    }
    return std::unexpected(pin_->pin_set() ? Status::PinInvalid : Status::PinNotSet);
  }
  return pin_->verify(*in.param, *in.protocol, client_data_hash, permission, rp_id);
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_client_pin(std::span<const std::uint8_t> body,
                                                                CancelToken& cancel) {
  return pin_->handle(body, cancel);
}

Result<std::unique_ptr<crypto::SigningKey>> Authenticator::load_key(const store::Credential& c) {
  if (!c.wrapped_id.empty()) return crypto::SoftwareKeyBackend::load_compact_private(c.priv, c.algorithm);
  if (c.backend == crypto::BackendKind::Software) {
    return software_.load_algorithm(c.priv, c.pub, c.algorithm, c.public_bytes);
  }
  if (primary_.kind() != c.backend) {
    log::error("key_backend_unavailable", {{"rp", c.rp_id},
                                           {"row_backend", backend_name(c.backend)},
                                           {"probed", backend_name(primary_.kind())}});
    return std::unexpected(Status::InvalidCredential);
  }
  auto k = primary_.load(c.handle, c.pub);
  if (!k) {
    log::error("key_load_failed", {{"rp", c.rp_id}, {"backend", backend_name(c.backend)}});
    return std::unexpected(Status::InvalidCredential);
  }
  return k;
}

void Authenticator::destroy_key(const store::Credential& c) {
  if (c.backend == crypto::BackendKind::Software) {
    (void)software_.destroy(c.priv);
    (void)software_.destroy_secret(c.cred_random);
  } else if (primary_.kind() == c.backend) {
    (void)primary_.destroy(c.handle);
    (void)primary_.destroy_secret(c.cred_random);
  } else {
    log::warn("destroy_skipped_backend_unavailable", {{"backend", backend_name(c.backend)}});
  }
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_reset(CancelToken& cancel, bool enforce_window) {
  if (enforce_window && std::chrono::steady_clock::now() - started_ >= cfg_.reset_window) {
    return std::unexpected(Status::NotAllowed);
  }
  static const std::array<std::uint8_t, 32> kZero{};
  const auto d = confirm_up(ui::PresenceRequest::Kind::Reset, "", "", kZero, cancel);
  if (d == ui::Decision::Cancelled) {
    return std::unexpected(Status::KeepaliveCancel);
  }
  if (d == ui::Decision::Timeout) {
    return std::unexpected(Status::UserActionTimeout);
  }
  if (d != ui::Decision::Allow) {
    return std::unexpected(Status::OperationDenied);
  }
  next_state_.reset();
  auto r = store_.factory_reset([this](const store::Credential& c) { destroy_key(c); });
  if (!r) {
    return std::unexpected(Status::Other);
  }
  (void)pin_->regenerate_key_agreement();  // drops the token and the ECDH key
  if (auto ri = primary_.reinit_after_reset(); !ri) {
    log::error("key_backend_reinit_failed", {{"backend", primary_backend_name()}});
    return std::unexpected(Status::Other);
  }
  log::warn("factory_reset");
  return std::vector<std::uint8_t>{};
}

// authenticatorSelection (0x0B): user presence only, empty response. Chrome
// uses it to let the user pick one of several plugged-in keys; answering
// INVALID_COMMAND makes Chrome drop this authenticator for the request.
Result<std::vector<std::uint8_t>> Authenticator::cmd_authenticator_selection(
    CancelToken& cancel) {
  static const std::array<std::uint8_t, 32> kZero{};
  const auto d = confirm_up(ui::PresenceRequest::Kind::Selection, "", "", kZero, cancel);
  if (d == ui::Decision::Cancelled) {
    return std::unexpected(Status::KeepaliveCancel);
  }
  if (d == ui::Decision::Timeout) {
    return std::unexpected(Status::UserActionTimeout);
  }
  if (d != ui::Decision::Allow) {
    return std::unexpected(Status::OperationDenied);
  }
  return std::vector<std::uint8_t>{};
}

Result<void> Authenticator::ctl_reset(CancelToken& cancel) {
  std::lock_guard<std::mutex> lk(op_mu_);
  auto r = cmd_reset(cancel, false);
  if (!r) {
    return std::unexpected(r.error());
  }
  return {};
}

Result<void> Authenticator::ctl_set_pin(std::string_view pin, CancelToken& cancel) {
  std::lock_guard<std::mutex> lk(op_mu_);
  static const std::array<std::uint8_t, 32> kZero{};
  const auto d = confirm_up(ui::PresenceRequest::Kind::SetPin, "", "", kZero, cancel);
  if (d == ui::Decision::Cancelled) {
    return std::unexpected(Status::KeepaliveCancel);
  }
  if (d == ui::Decision::Timeout) {
    return std::unexpected(Status::UserActionTimeout);
  }
  if (d != ui::Decision::Allow) {
    return std::unexpected(Status::OperationDenied);
  }
  return pin_->set_pin_local(pin);
}

Result<void> Authenticator::ctl_delete(std::span<const std::uint8_t> cred_id) {
  std::lock_guard<std::mutex> lk(op_mu_);
  auto row = store_.find_by_id(cred_id);
  if (!row) {
    return std::unexpected(Status::InvalidCredential);
  }
  if (auto r = store_.erase(cred_id); !r) return r;
  destroy_key(*row);
  next_state_.reset(); management_state_.reset();
  return {};
}

Result<std::vector<std::uint8_t>> Authenticator::handle_cbor(
    std::span<const std::uint8_t> request, CancelToken& cancel) {
  return handle_cbor_channel(request, cancel, 0);
}
Result<std::vector<std::uint8_t>> Authenticator::handle_cbor_channel(
    std::span<const std::uint8_t> request, CancelToken& cancel, std::uint32_t channel) {
  std::lock_guard<std::mutex> lk(op_mu_);
  if (state_channel_ != channel) {
    next_state_.reset(); management_state_.reset();
    large_blob_pending_.clear(); large_blob_expected_ = 0;
    state_channel_ = channel;
  }
  if (request.empty()) {
    return std::unexpected(Status::InvalidLength);
  }
  const std::uint8_t cmd = request[0];
  const auto body = request.subspan(1);
  if (request.size() > profile::max_message_size) return std::unexpected(Status::RequestTooLarge);
  if (cmd != kCmdCredentialManagement && cmd != kCmdCredentialManagementPreview) management_state_.reset();
  if (cmd != kCmdLargeBlobs) { large_blob_pending_.clear(); large_blob_expected_ = 0; }
  if (!body.empty()) {
    if (auto v = cbor::validate_ctap(body); !v) return std::unexpected(v.error());
  }
  if ((cmd == kCmdGetInfo || cmd == kCmdGetNextAssertion || cmd == kCmdReset || cmd == kCmdAuthenticatorSelection) && !body.empty())
    return std::unexpected(Status::InvalidLength);
  const auto t0 = std::chrono::steady_clock::now();
  if (cmd != kCmdGetNextAssertion) {
    next_state_.reset();  // CTAP 2.1: any other command invalidates the pending list
  }
  Result<std::vector<std::uint8_t>> r;
  switch (cmd) {
    case kCmdCredentialManagementPreview:
      r = cmd_credential_management(body, true); break;
    case kCmdCredentialManagement:
      r = cmd_credential_management(body); break;
    case kCmdLargeBlobs:
      r = cmd_large_blobs(body); break;
    case kCmdAuthenticatorConfig:
      r = cmd_authenticator_config(body); break;
    case kCmdGetInfo:
      r = cmd_get_info();
      break;
    case kCmdMakeCredential:
      r = cmd_make_credential(body, cancel);
      break;
    case kCmdGetAssertion:
      r = cmd_get_assertion(body, cancel);
      break;
    case kCmdGetNextAssertion:
      r = cmd_get_next_assertion();
      break;
    case kCmdReset:
      r = cmd_reset(cancel);
      break;
    case kCmdClientPin:
      r = cmd_client_pin(body, cancel);
      break;
    case kCmdAuthenticatorSelection:
      r = cmd_authenticator_selection(cancel);
      break;
    default:
      r = std::unexpected(Status::InvalidCommand);
      break;
  }
  const std::uint8_t status = r ? 0 : static_cast<std::uint8_t>(r.error());
  count_status(status);
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0);
  char cmd_hex[5];
  std::snprintf(cmd_hex, sizeof cmd_hex, "0x%02x", static_cast<unsigned>(cmd));
  log::info("ctap", {{"cmd", cmd_name(cmd)},
                     {"cmd_byte", cmd_hex},
                     {"status", std::to_string(status)},
                     {"ms", std::to_string(ms.count())}});
  return r;
}

}  // namespace swpk::ctap

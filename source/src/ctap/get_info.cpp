#include "swpasskey/ctap/get_info.hpp"

#include "swpasskey/cbor/cbor.hpp"

#include <utility>

namespace swpk::ctap {
namespace {

using Entry = std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>;
using cbor::Writer;

std::vector<std::uint8_t> encode_tstr_array(const std::vector<std::string>& v) {
  Writer w;
  w.write_array_header(v.size());
  for (const auto& s : v) {
    w.write_tstr(s);
  }
  return w.finish();
}

}  // namespace

std::vector<std::uint8_t> encode_get_info(const GetInfoSnapshot& s) {
  std::vector<Entry> top;
  top.emplace_back(Writer::encode_uint(1), encode_tstr_array(s.versions));
  if (!s.extensions.empty()) {
    top.emplace_back(Writer::encode_uint(2), encode_tstr_array(s.extensions));
  }
  top.emplace_back(Writer::encode_uint(3), Writer::encode_bstr(s.aaguid));

  {
    std::vector<Entry> opts;
    opts.emplace_back(Writer::encode_tstr("alwaysUv"), Writer::encode_bool(s.options.always_uv));
    if (s.options.client_pin.has_value()) {
      opts.emplace_back(Writer::encode_tstr("clientPin"),
                        Writer::encode_bool(*s.options.client_pin));
    }
    opts.emplace_back(Writer::encode_tstr("credMgmt"), Writer::encode_bool(s.options.cred_mgmt));
    if (s.options.cred_mgmt) opts.emplace_back(Writer::encode_tstr("credentialMgmtPreview"), Writer::encode_bool(true));
    if (s.options.large_blobs) opts.emplace_back(Writer::encode_tstr("largeBlobs"), Writer::encode_bool(true));
    if (s.options.authnr_cfg) opts.emplace_back(Writer::encode_tstr("authnrCfg"), Writer::encode_bool(true));
    if (s.options.set_min_pin_length) opts.emplace_back(Writer::encode_tstr("setMinPINLength"), Writer::encode_bool(true));
    opts.emplace_back(Writer::encode_tstr("makeCredUvNotRqd"),
                      Writer::encode_bool(s.options.make_cred_uv_not_rqd));
    if (s.options.pin_uv_auth_token.has_value()) {
      opts.emplace_back(Writer::encode_tstr("pinUvAuthToken"),
                        Writer::encode_bool(*s.options.pin_uv_auth_token));
    }
    opts.emplace_back(Writer::encode_tstr("plat"), Writer::encode_bool(s.options.plat));
    opts.emplace_back(Writer::encode_tstr("rk"), Writer::encode_bool(s.options.rk));
    opts.emplace_back(Writer::encode_tstr("up"), Writer::encode_bool(s.options.up));
    Writer w;
    w.write_map(std::move(opts));
    top.emplace_back(Writer::encode_uint(4), w.finish());
  }

  top.emplace_back(Writer::encode_uint(5), Writer::encode_uint(s.max_msg_size));
  if (!s.pin_protocols.empty()) {
    Writer w;
    w.write_array_header(s.pin_protocols.size());
    for (auto p : s.pin_protocols) {
      w.write_uint(p);
    }
    top.emplace_back(Writer::encode_uint(6), w.finish());
  }
  top.emplace_back(Writer::encode_uint(7), Writer::encode_uint(s.max_creds_in_list));
  top.emplace_back(Writer::encode_uint(8), Writer::encode_uint(s.max_cred_id_len));
  top.emplace_back(Writer::encode_uint(9), encode_tstr_array(s.transports));
  {
    Writer w;
    w.write_array_header(s.algorithms.size());
    for (int alg : s.algorithms) {
      std::vector<Entry> m;
      m.emplace_back(Writer::encode_tstr("alg"), Writer::encode_int(alg));
      m.emplace_back(Writer::encode_tstr("type"), Writer::encode_tstr("public-key"));
      Writer inner;
      inner.write_map(std::move(m));
      w.write_raw(inner.finish());
    }
    top.emplace_back(Writer::encode_uint(10), w.finish());
  }
  if (s.max_large_blob_array) top.emplace_back(Writer::encode_uint(11), Writer::encode_uint(*s.max_large_blob_array));
  if (s.force_pin_change) top.emplace_back(Writer::encode_uint(12), Writer::encode_bool(*s.force_pin_change));
  if (s.min_pin_length) top.emplace_back(Writer::encode_uint(13), Writer::encode_uint(*s.min_pin_length));
  if (s.max_cred_blob_length) top.emplace_back(Writer::encode_uint(15), Writer::encode_uint(*s.max_cred_blob_length));
  if (s.max_min_pin_rp_ids) top.emplace_back(Writer::encode_uint(16), Writer::encode_uint(*s.max_min_pin_rp_ids));
  top.emplace_back(Writer::encode_uint(14), Writer::encode_uint(s.firmware_version));
  top.emplace_back(Writer::encode_uint(20), Writer::encode_uint(s.remaining_discoverable));

  Writer w;
  w.write_map(std::move(top));
  return w.finish();
}

}  // namespace swpk::ctap

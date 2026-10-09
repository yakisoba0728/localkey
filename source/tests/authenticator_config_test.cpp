#include "swpasskey/cbor/cbor.hpp"
#include "swpasskey/ctap/authenticator.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>
#include <vector>

using namespace swpk;

namespace {
using Entry = std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>;
using cbor::Writer;

std::vector<std::uint8_t> set_min_pin_length(std::vector<std::string> rp_ids,
                                             std::uint64_t length) {
  Writer ids;
  ids.write_array_header(rp_ids.size());
  for (const auto& id : rp_ids) ids.write_tstr(id);
  Writer params;
  params.write_map({
      {Writer::encode_uint(1), Writer::encode_uint(length)},
      {Writer::encode_uint(2), ids.finish()},
  });
  Writer command;
  command.write_map({
      {Writer::encode_uint(1), Writer::encode_uint(3)},
      {Writer::encode_uint(2), params.finish()},
  });
  auto body = command.finish();
  std::vector<std::uint8_t> request{ctap::kCmdAuthenticatorConfig};
  request.insert(request.end(), body.begin(), body.end());
  return request;
}
}  // namespace

TEST_CASE("empty minPinLengthRPIDs leaves the prior allowlist intact", "[ctap-config]") {
  crypto::Provider crypto;
  crypto::SoftwareKeyBackend keys;
  auto store = store::CredentialStore::open_memory();
  ui::AlwaysDenyPresence presence;
  ctap::Authenticator auth{ctap::AuthenticatorConfig{}, crypto, keys, keys, *store, presence};
  ctap::CancelToken cancel;

  const auto first = set_min_pin_length({"example.com"}, 4);
  REQUIRE(auth.handle_cbor(first, cancel).has_value());
  REQUIRE(store->pin().min_length_rp_ids == std::vector<std::string>{"example.com"});

  // CTAP 2.1 §6.11.4 step 7 updates the RP-ID list only if it has a string.
  const auto empty = set_min_pin_length({}, 5);
  REQUIRE(auth.handle_cbor(empty, cancel).has_value());
  REQUIRE(store->pin().min_length == 5);
  REQUIRE(store->pin().min_length_rp_ids == std::vector<std::string>{"example.com"});
}

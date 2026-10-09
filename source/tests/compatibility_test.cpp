#include "ctap_test_util.hpp"
#include "swpasskey/text.hpp"
#include <catch2/catch_test_macros.hpp>
using namespace swpk;
using namespace swpk::test;
TEST_CASE("wire reset expires after power-up window", "[reset][compat]") {
  Rig rig;
  REQUIRE_FALSE(rig.register_cred({}).empty());
  ctap::AuthenticatorConfig cfg;
  cfg.reset_window = std::chrono::milliseconds{0};
  ctap::Authenticator auth(cfg, rig.crypto, rig.software, rig.software, *rig.store, rig.presence);
  REQUIRE(auth.handle_cbor(bytes({ctap::kCmdReset}), rig.tok).error() == Status::NotAllowed);
  REQUIRE(rig.store->size() == 1);
}
TEST_CASE("pending assertions cannot be consumed by a different HID channel", "[ga][compat]") {
  Rig rig;
  MakeCredOpts a; a.user_id = {1}; REQUIRE_FALSE(rig.register_cred(a).empty());
  a.user_id = {2}; REQUIRE_FALSE(rig.register_cred(a).empty());
  auto first = rig.auth->handle_cbor_channel(get_assert_request({}), rig.tok, 123);
  REQUIRE(first);
  const auto next = bytes({ctap::kCmdGetNextAssertion});
  REQUIRE(rig.auth->handle_cbor_channel(next, rig.tok, 456).error() == Status::NotAllowed);
}
TEST_CASE("CTAP rejects duplicate keys, overlong integers, invalid Unicode and trailing data", "[cbor][compat]") {
  const auto duplicate = bytes({0xa2, 1, 1, 1, 2});
  const auto overlong = bytes({0xa1, 0x18, 1, 1});
  const auto unicode = bytes({0xa1, 1, 0x62, 0xc0, 0x80});
  const auto trailing = bytes({0xa0, 0});
  for (const auto& bad : {duplicate, overlong, unicode, trailing}) {
    auto req = bad; req.insert(req.begin(), ctap::kCmdMakeCredential);
    Rig rig; REQUIRE(rig.call(req).error() == Status::InvalidCbor);
  }
  REQUIRE(utf8_code_points(bytes({0xf0, 0x9f, 0x94, 0x91})) == 1);
  REQUIRE_FALSE(utf8_code_points(bytes({0xed, 0xa0, 0x80})));
}
TEST_CASE("CTAP ignores unknown canonical float-valued fields", "[cbor][compat]") {
  Rig rig;
  const std::array<std::uint8_t, 32> challenge{};
  for (const auto& float_value : {
           bytes({0xf9, 0x00, 0x00}),
           bytes({0xf9, 0x3c, 0x00}),
           bytes({0xfa, 0x3f, 0x80, 0x00, 0x00}),
           bytes({0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})}) {
    Writer w;
    w.write_map({
        {Writer::encode_uint(1), Writer::encode_tstr("unknown.example")},
        {Writer::encode_uint(2), Writer::encode_bstr(challenge)},
        {Writer::encode_uint(8), float_value},
    });
    auto request = w.finish();
    request.insert(request.begin(), ctap::kCmdGetAssertion);
    REQUIRE(rig.call(request).error() == Status::NoCredentials);
  }
  Writer w;
  w.write_map({
      {Writer::encode_uint(1), Writer::encode_tstr("unknown.example")},
      {Writer::encode_uint(2), Writer::encode_bstr(challenge)},
      {Writer::encode_uint(8), bytes({0xf9, 0x00})},
  });
  auto malformed = w.finish();
  malformed.insert(malformed.begin(), ctap::kCmdGetAssertion);
  REQUIRE(rig.call(malformed).error() == Status::InvalidCbor);
}
TEST_CASE("Ed25519 and P384 stay software backed when the primary backend is hardware", "[crypto][compat]") {
  Rig rig(true);
  for (int alg : {-8, -35}) {
    MakeCredOpts o; o.alg = alg; o.user_id = {static_cast<std::uint8_t>(-alg)};
    auto r = rig.call(make_cred_request(o)); REQUIRE(r);
    const auto rows = rig.store->all();
    const auto& c = rows.back();
    REQUIRE(c.algorithm == alg); REQUIRE(c.backend == crypto::BackendKind::Software);
    REQUIRE(c.handle.empty()); REQUIRE_FALSE(c.priv.empty());
    auto key = rig.software.load_algorithm(c.priv, c.pub, c.algorithm, c.public_bytes);
    REQUIRE(key);
    auto corrupted = c.public_bytes; corrupted[0] ^= 1;
    REQUIRE_FALSE(rig.software.load_algorithm(c.priv, c.pub, c.algorithm, corrupted));
  }
}

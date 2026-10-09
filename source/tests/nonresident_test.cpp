#include "ctap_test_util.hpp"
#include <catch2/catch_test_macros.hpp>

using namespace swpk;
using namespace swpk::test;

TEST_CASE("software nonresident registrations exceed the former 10000-row limit without storage growth", "[nonresident]") {
  Rig rig;
  MakeCredOpts request; request.rk = false;
  auto first = rig.register_cred(request); REQUIRE(first.size() == 128);
  const auto original = rig.store->serialize();
  std::vector<std::uint8_t> last;
  for (std::size_t i = 0; i < 10000; ++i) {
    last = rig.register_cred(request);
    REQUIRE(last.size() == 128);
  }
  REQUIRE(first != last);
  REQUIRE(rig.store->size() == 0);
  REQUIRE(rig.store->remaining() == 100);
  REQUIRE(rig.store->serialize() == original);
  GetAssertOpts assertion; assertion.allow = std::vector<std::vector<std::uint8_t>>{first, last, first};
  auto response = rig.call(get_assert_request(assertion)); REQUIRE(response);
  auto values = split_int_map(*response);
  REQUIRE_FALSE(values.contains(4));
  REQUIRE(rig.store->nonresident_counter() == 2);
  REQUIRE(rig.call(bytes({ctap::kCmdGetNextAssertion})));
  REQUIRE(rig.store->nonresident_counter() == 3);
  REQUIRE(rig.call(bytes({ctap::kCmdGetNextAssertion})).error() == Status::NotAllowed);
}

TEST_CASE("wrapped credentials survive reload and reject another RP, tampering, reset and another install", "[nonresident]") {
  Rig rig;
  MakeCredOpts request; request.rk = false;
  const auto id = rig.register_cred(request); REQUIRE(id.size() == 128);
  const auto snapshot = rig.store->serialize();
  auto reopened = store::CredentialStore::open_with(snapshot, nullptr); REQUIRE(reopened);
  ctap::Authenticator auth({}, rig.crypto, rig.software, rig.software, **reopened, rig.presence);
  GetAssertOpts assertion; assertion.allow = std::vector<std::vector<std::uint8_t>>{id};
  REQUIRE(auth.handle_cbor(get_assert_request(assertion), rig.tok));
  assertion.rp_id = "different.example";
  REQUIRE(auth.handle_cbor(get_assert_request(assertion), rig.tok).error() == Status::NoCredentials);
  assertion.rp_id = "example.com";
  for (std::size_t offset : {0U, 3U, 4U, 16U, 52U, 127U}) {
    auto broken = id; broken[offset] ^= 1;
    assertion.allow = std::vector<std::vector<std::uint8_t>>{broken};
    REQUIRE(auth.handle_cbor(get_assert_request(assertion), rig.tok).error() == Status::NoCredentials);
  }
  assertion.allow = std::vector<std::vector<std::uint8_t>>{id};
  Rig unrelated;
  REQUIRE(unrelated.call(get_assert_request(assertion)).error() == Status::NoCredentials);
  REQUIRE(auth.ctl_reset(rig.tok));
  REQUIRE_FALSE((*reopened)->nonresident_key());
  REQUIRE(auth.handle_cbor(get_assert_request(assertion), rig.tok).error() == Status::NoCredentials);
}

TEST_CASE("wrapped IDs authenticate excludeList and preserve credProtect restrictions", "[nonresident]") {
  Rig rig;
  MakeCredOpts request; request.rk = false;
  const auto id = rig.register_cred(request); REQUIRE(id.size() == 128);
  request.exclude = {id};
  REQUIRE(rig.call(make_cred_request(request)).error() == Status::CredentialExcluded);
  request.rp_id = "unrelated.example";
  REQUIRE(rig.call(make_cred_request(request)));
  request.rp_id = "example.com"; request.exclude.clear(); request.cred_protect = 3;
  const auto protected_id = rig.register_cred(request); REQUIRE(protected_id.size() == 128);
  GetAssertOpts assertion; assertion.allow = std::vector<std::vector<std::uint8_t>>{protected_id};
  REQUIRE(rig.call(get_assert_request(assertion)).error() == Status::NoCredentials);
  assertion.allow.reset();
  REQUIRE(rig.call(get_assert_request(assertion)).error() == Status::NoCredentials);
}

TEST_CASE("compact private keys preserve all three algorithms and reject invalid EC scalars", "[nonresident][crypto]") {
  crypto::SoftwareKeyBackend backend;
  for (int algorithm : {-7, -8, -35}) {
    auto original = backend.generate_algorithm(algorithm); REQUIRE(original);
    const auto compact = (*original)->export_compact_private();
    REQUIRE(compact.size() == (algorithm == -35 ? 48U : 32U));
    auto restored = crypto::SoftwareKeyBackend::load_compact_private(compact, algorithm); REQUIRE(restored);
    REQUIRE((*restored)->public_bytes() == (*original)->public_bytes());
    REQUIRE((*restored)->sign_der(bytes({1, 2, 3})));
  }
  for (int algorithm : {-7, -35}) {
    const std::size_t length = algorithm == -7 ? 32U : 48U;
    REQUIRE_FALSE(crypto::SoftwareKeyBackend::load_compact_private(std::vector<std::uint8_t>(length), algorithm));
    REQUIRE_FALSE(crypto::SoftwareKeyBackend::load_compact_private(std::vector<std::uint8_t>(length, 255), algorithm));
  }
}

TEST_CASE("nonresident root and counter writes roll back on persistence failure", "[nonresident][store]") {
  struct Writer final : store::Persister {
    bool& rejected;
    explicit Writer(bool& r) : rejected(r) {}
    Result<void> save(std::span<const std::uint8_t>) override {
      if (rejected) return std::unexpected(Status::Other);
      return {};
    }
  };
  Rig rig;
  bool rejected = true;
  auto reopened = store::CredentialStore::open_with({}, std::make_unique<Writer>(rejected)); REQUIRE(reopened);
  ctap::Authenticator auth({}, rig.crypto, rig.software, rig.software, **reopened, rig.presence);
  MakeCredOpts request; request.rk = false;
  REQUIRE(auth.handle_cbor(make_cred_request(request), rig.tok).error() == Status::Other);
  REQUIRE_FALSE((*reopened)->nonresident_key());
  rejected = false;
  auto registration = auth.handle_cbor(make_cred_request(request), rig.tok); REQUIRE(registration);
  const auto map = split_int_map(*registration);
  const auto registered = parse_auth_data(as_bstr(map.at(2)));
  GetAssertOpts assertion; assertion.allow = std::vector<std::vector<std::uint8_t>>{registered.cred_id};
  const auto saved = (*reopened)->serialize();
  rejected = true;
  REQUIRE(auth.handle_cbor(get_assert_request(assertion), rig.tok).error() == Status::Other);
  REQUIRE((*reopened)->nonresident_counter() == 1);
  REQUIRE((*reopened)->serialize() == saved);
  rejected = false;
  auto response = auth.handle_cbor(get_assert_request(assertion), rig.tok); REQUIRE(response);
  const auto fields = split_int_map(*response);
  const auto data = as_bstr(fields.at(2));
  auto message = data; message.insert(message.end(), assertion.client_data_hash.begin(), assertion.client_data_hash.end());
  REQUIRE(verify_es256(registered.pub, message, as_bstr(fields.at(3))));
  REQUIRE(parse_auth_data(data).sign_count == 2);
}

TEST_CASE("shared wrapped counter reaches its maximum without wrapping or issuing another UP signature", "[nonresident][store][u2f]") {
  Rig rig;
  MakeCredOpts request; request.rk = false;
  const auto id = rig.register_cred(request);
  auto fields = split_text_map(rig.store->serialize());
  fields["nonresident_counter"] = cbor::Writer::encode_uint(UINT32_MAX - 1);
  std::vector<Entry> entries;
  for (auto& [name, value] : fields)
    entries.emplace_back(cbor::Writer::encode_tstr(name), std::move(value));
  cbor::Writer writer; writer.write_map(std::move(entries));
  auto reopened = store::CredentialStore::open_with(writer.finish(), nullptr); REQUIRE(reopened);
  ctap::Authenticator auth({.u2f_enabled = true}, rig.crypto, rig.software, rig.software, **reopened, rig.presence);
  GetAssertOpts assertion; assertion.allow = std::vector<std::vector<std::uint8_t>>{id};
  auto last = auth.handle_cbor(get_assert_request(assertion), rig.tok); REQUIRE(last);
  REQUIRE(parse_auth_data(as_bstr(split_int_map(*last).at(2))).sign_count == UINT32_MAX);
  const auto saturated = (*reopened)->serialize();
  REQUIRE(auth.handle_cbor(get_assert_request(assertion), rig.tok).error() == Status::LimitExceeded);
  assertion.up = false;
  auto preflight = auth.handle_cbor(get_assert_request(assertion), rig.tok); REQUIRE(preflight);
  REQUIRE(parse_auth_data(as_bstr(split_int_map(*preflight).at(2))).sign_count == UINT32_MAX);
  const auto rp_hash = rig.crypto.sha256(std::span<const std::uint8_t>(
    reinterpret_cast<const std::uint8_t*>(request.rp_id.data()), request.rp_id.size()));
  std::vector<std::uint8_t> body(assertion.client_data_hash.begin(), assertion.client_data_hash.end());
  body.insert(body.end(), rp_hash.begin(), rp_hash.end());
  body.push_back(static_cast<std::uint8_t>(id.size())); body.insert(body.end(), id.begin(), id.end());
  std::vector<std::uint8_t> apdu{0, 2, 3, 0, static_cast<std::uint8_t>(body.size())};
  apdu.insert(apdu.end(), body.begin(), body.end());
  REQUIRE(auth.handle_u2f(apdu, rig.tok) == bytes({0x6F, 0x00}));
  apdu[2] = 7;
  REQUIRE(auth.handle_u2f(apdu, rig.tok) == bytes({0x69, 0x85}));
  REQUIRE((*reopened)->serialize() == saturated);
}

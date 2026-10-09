#include "swpasskey/hid/iokit_report_inbox.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <algorithm>
#include <cstdint>

using namespace swpk::hid;

TEST_CASE("macOS CTAPHID output accepts only a full report with optional zero ID", "[hid][iokit]") {
  Report raw{};
  for (std::size_t i = 0; i < raw.size(); ++i) raw[i] = static_cast<std::uint8_t>(i);
  auto exact = normalize_iokit_output(0, raw);
  REQUIRE(exact.has_value());
  REQUIRE(*exact == raw);

  std::array<std::uint8_t, kReportSize + 1> prefixed{};
  std::copy(raw.begin(), raw.end(), prefixed.begin() + 1);
  REQUIRE(normalize_iokit_output(0, prefixed) == raw);
  prefixed[0] = 1;
  REQUIRE_FALSE(normalize_iokit_output(0, prefixed).has_value());
  REQUIRE_FALSE(normalize_iokit_output(1, raw).has_value());
  REQUIRE_FALSE(normalize_iokit_output(0, std::span(raw).first(63)).has_value());
  std::array<std::uint8_t, kReportSize + 2> oversized{};
  REQUIRE_FALSE(normalize_iokit_output(0, oversized).has_value());
}

TEST_CASE("macOS CTAPHID inbox never silently drops accepted report order", "[hid][iokit]") {
  IokitReportInbox inbox;
  Report raw{};
  for (std::size_t i = 0; i < IokitReportInbox::kCapacity; ++i) {
    raw[0] = static_cast<std::uint8_t>(i);
    REQUIRE(inbox.push(raw));
  }
  raw[0] = 0xee;
  REQUIRE_FALSE(inbox.push(raw));
  REQUIRE(inbox.size() == IokitReportInbox::kCapacity);
  for (std::size_t i = 0; i < IokitReportInbox::kCapacity; ++i) {
    auto report = inbox.pop();
    REQUIRE(report.has_value());
    REQUIRE((*report)[0] == static_cast<std::uint8_t>(i));
  }
  REQUIRE(inbox.empty());
  REQUIRE_FALSE(inbox.pop().has_value());
}

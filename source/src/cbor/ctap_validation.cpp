#include "swpasskey/cbor/cbor.hpp"
#include "swpasskey/text.hpp"
#include <algorithm>
namespace swpk::cbor {
namespace {
Result<void> item(std::span<const std::uint8_t> data, std::size_t& pos, unsigned depth) {
  if (depth > 16 || pos >= data.size()) return std::unexpected(Status::InvalidCbor);
  const auto head = data[pos++];
  const unsigned major = head >> 5, ai = head & 31U;
  // CTAP2 canonical CBOR permits all three IEEE-754 float widths. Unknown
  // command map keys must be ignored even when their values are floats.
  if (major == 6 || (major == 7 && ai != 20 && ai != 21 && ai != 22 &&
                     ai != 25 && ai != 26 && ai != 27))
    return std::unexpected(Status::InvalidCbor);
  if (ai >= 28) return std::unexpected(Status::InvalidCbor);
  std::uint64_t value = ai;
  if (ai >= 24) {
    const unsigned bytes = 1U << (ai - 24);
    if (data.size() - pos < bytes) return std::unexpected(Status::InvalidCbor);
    value = 0;
    for (unsigned i = 0; i < bytes; ++i) value = (value << 8) | data[pos++];
    const auto minimum = bytes == 1 ? 24ULL : bytes == 2 ? 256ULL : bytes == 4 ? 65536ULL : 4294967296ULL;
    // Float width is part of the CBOR value; its payload bits do not obey
    // the minimal-integer-length rule (e.g. +0.0 has all-zero payload bits).
    if (major != 7 && value < minimum) return std::unexpected(Status::InvalidCbor);
  }
  if (major == 2 || major == 3) {
    if (value > data.size() - pos) return std::unexpected(Status::InvalidCbor);
    if (major == 3 && !utf8_code_points(data.subspan(pos, static_cast<std::size_t>(value))))
      return std::unexpected(Status::InvalidCbor);
    pos += static_cast<std::size_t>(value);
  } else if (major == 4 || major == 5) {
    // Every array member/map key consumes at least one byte.
    if (value > data.size() - pos) return std::unexpected(Status::InvalidCbor);
    std::span<const std::uint8_t> previous;
    for (std::uint64_t i = 0; i < value; ++i) {
      const auto start = pos;
      if (auto v = item(data, pos, depth + 1); !v) return v;
      if (major == 5) {
        const auto key = data.subspan(start, pos - start);
        if (i && !std::lexicographical_compare(previous.begin(), previous.end(), key.begin(), key.end()))
          return std::unexpected(Status::InvalidCbor);
        previous = key;
        if (auto v = item(data, pos, depth + 1); !v) return v;
      }
    }
  }
  return {};
}
}  // namespace
Result<void> validate_ctap(std::span<const std::uint8_t> data) {
  std::size_t pos = 0;
  if (auto v = item(data, pos, 0); !v) return v;
  if (pos != data.size()) return std::unexpected(Status::InvalidCbor);
  return {};
}
}  // namespace swpk::cbor

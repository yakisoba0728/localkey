#pragma once
#include "swpasskey/status.hpp"
#include <cstdint>
#include <span>
#include <cstddef>
namespace swpk {
inline Result<std::size_t> utf8_code_points(std::span<const std::uint8_t> s) {
  std::size_t count = 0;
  for (std::size_t i = 0; i < s.size(); ++count) {
    const auto c = s[i++];
    if (c < 0x80) continue;
    unsigned n = 0; std::uint32_t value = 0, minimum = 0;
    if (c >= 0xc2 && c <= 0xdf) { n = 1; value = c & 0x1fU; minimum = 0x80; }
    else if (c >= 0xe0 && c <= 0xef) { n = 2; value = c & 0x0fU; minimum = 0x800; }
    else if (c >= 0xf0 && c <= 0xf4) { n = 3; value = c & 0x07U; minimum = 0x10000; }
    else return std::unexpected(Status::InvalidParameter);
    if (s.size() - i < n) return std::unexpected(Status::InvalidParameter);
    while (n--) {
      const auto b = s[i++]; if ((b & 0xc0U) != 0x80U) return std::unexpected(Status::InvalidParameter);
      value = (value << 6) | (b & 0x3fU);
    }
    if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
      return std::unexpected(Status::InvalidParameter);
  }
  return count;
}
}  // namespace swpk

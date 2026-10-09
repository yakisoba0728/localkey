#pragma once

#include <cstddef>
#include <cstdint>

namespace swpk::usb {
// Measured public USB profile; see usb-reference-observation.json.
inline constexpr std::size_t kCcidMessageLength = 3072;
inline constexpr std::size_t kCcidPayloadLength = kCcidMessageLength - 10;
inline constexpr std::size_t kMaxCommandApduLength = 65544;
inline constexpr std::size_t kMaxResponseApduLength = 65538;
inline constexpr std::uint8_t kFidoOut = 0x04, kFidoIn = 0x84;
inline constexpr std::uint8_t kCcidOut = 0x02, kCcidIn = 0x82, kCcidInterrupt = 0x83;
}  // namespace swpk::usb

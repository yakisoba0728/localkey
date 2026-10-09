#pragma once

#include <cstddef>
#include <cstdint>

namespace swpk::ctap::profile {
// Public limits read from the reference's GetInfo. The software authenticator
// retains its own AAGUID and monotonically increasing software firmware revision.
inline constexpr std::size_t max_message_size = 1536;
inline constexpr std::uint32_t max_credential_id_length = 128;
inline constexpr std::uint32_t max_min_pin_rp_ids = 1;
inline constexpr std::size_t max_large_blob_fragment = max_message_size - 64;
inline constexpr std::uint32_t firmware_revision = 3;
}  // namespace swpk::ctap::profile

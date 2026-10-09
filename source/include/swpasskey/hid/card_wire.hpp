#pragma once

#include "swpasskey/status.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace swpk::hid {
// Same-user, private Unix socket RPC to the shared CCID/OTP management core.
// Identity=0xff; enabled USB capabilities=0; device read/write=0x42/0x43.
Result<std::vector<std::uint8_t>> card_command(
    const std::string& path, std::uint8_t command, std::span<const std::uint8_t> data = {});
}

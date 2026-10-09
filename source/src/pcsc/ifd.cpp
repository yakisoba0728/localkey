#include "swpasskey/pcsc/ifd_api.hpp"
#include "swpasskey/pcsc/reader.hpp"

#include <cstring>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace {
using swpk::pcsc::Reader;
constexpr RESPONSECODE success = 0, error_tag = 600, read_only = 602,
    pts_failure = 605, unsupported = 606, protocol_unsupported = 607,
    power_error = 608, communication_error = 612, present = 615,
    absent = 616, no_device = 617, insufficient_buffer = 618;
constexpr DWORD max_readers = 16;
std::mutex readers_mutex;
std::unordered_map<DWORD, std::shared_ptr<Reader>> readers;

template<class Operation>
RESPONSECODE on_reader(DWORD lun, Operation operation) noexcept {
  try {
    std::shared_ptr<Reader> reader;
    {
      std::lock_guard lock(readers_mutex);
      const auto found = readers.find(lun);
      if (found == readers.end()) return no_device;
      reader = found->second;
    }
    std::lock_guard lock(reader->mutex);
    return operation(*reader);
  } catch (const swpk::pcsc::WireError& error) {
    return static_cast<RESPONSECODE>(error.code);
  } catch (...) {
    return communication_error;
  }
}
RESPONSECODE copy_output(std::span<const std::uint8_t> data, PUCHAR buffer, PDWORD length) {
  if (!length) return communication_error;
  const auto available = *length;
  *length = 0;
  if (data.size() > available) return insufficient_buffer;
  if (!data.empty()) {
    if (!buffer) return communication_error;
    std::memcpy(buffer, data.data(), data.size());
  }
  *length = static_cast<DWORD>(data.size());
  return success;
}
RESPONSECODE copy_string(const std::string& value, PUCHAR buffer, PDWORD length) {
  return copy_output({reinterpret_cast<const std::uint8_t*>(value.c_str()), value.size() + 1}, buffer, length);
}
}  // namespace

RESPONSECODE IFDHCreateChannelByName(DWORD lun, LPSTR name) {
  if (!name || (lun & 0xffff) || (lun >> 16) >= max_readers) return no_device;
  try {
    std::lock_guard lock(readers_mutex);
    if (readers.contains(lun)) return communication_error;
    readers.emplace(lun, std::make_shared<Reader>(name));
    return success;
  } catch (const swpk::pcsc::WireError& error) {
    return static_cast<RESPONSECODE>(error.code);
  } catch (...) { return communication_error; }
}
RESPONSECODE IFDHCreateChannel(DWORD lun, DWORD channel) {
  if (channel != 0) return no_device;
  const auto* value = std::getenv("SWPASSKEY_CCID_SOCKET");
  return value ? IFDHCreateChannelByName(lun, const_cast<char*>(value)) : no_device;
}
RESPONSECODE IFDHCloseChannel(DWORD lun) {
  try {
  std::shared_ptr<Reader> reader;
  {
    std::lock_guard lock(readers_mutex);
    const auto found = readers.find(lun);
    if (found == readers.end()) return no_device;
    reader = found->second;
    readers.erase(found);
  }
  std::lock_guard lock(reader->mutex);
  reader->close();
  return success;
  } catch (...) { return communication_error; }
}
RESPONSECODE IFDHGetCapabilities(DWORD lun, DWORD tag, PDWORD length, PUCHAR value) {
  if (!length) return communication_error;
  const auto available = *length;
  *length = 0;
  const auto result = on_reader(lun, [&](Reader& reader) -> RESPONSECODE {
    *length = available;
    const auto scalar = [&](std::uint8_t n) { return copy_output({&n, 1}, value, length); };
    switch (tag) {
      case 0x0303: return copy_output(reader.atr, value, length);
      case 0x0180: return scalar(0);
      case 0x0fac: case 0x0fad: case 0x0fae: return scalar(1);
      case 0x0faf: return scalar(max_readers);
      case 0x0100: return copy_string("Local software emulator", value, length);
      case 0x0101: return copy_string("Private CCID socket reader", value, length);
      case 0x0103: return copy_string(reader.serial, value, length);
      case 0x0102: {
        constexpr DWORD version = 0x002a0000;
        return copy_output({reinterpret_cast<const std::uint8_t*>(&version), sizeof(version)}, value, length);
      }
      default: *length = 0; return error_tag;
    }
  });
  if (result != success) *length = 0;
  return result;
}
RESPONSECODE IFDHSetCapabilities(DWORD lun, DWORD tag, DWORD, PUCHAR) {
  return on_reader(lun, [&](Reader&) -> RESPONSECODE {
    switch (tag) {
      case 0x0303: case 0x0180: case 0x0fac: case 0x0fad: case 0x0fae:
      case 0x0faf: case 0x0100: case 0x0101: case 0x0102: case 0x0103:
        return read_only;
      default: return error_tag;
    }
  });
}
RESPONSECODE IFDHSetProtocolParameters(DWORD lun, DWORD protocol, UCHAR flags, UCHAR, UCHAR, UCHAR) {
  return on_reader(lun, [&](Reader&) -> RESPONSECODE {
    // The independent software ATR declares T=1. The preference is a bitmask.
    if (protocol != 2) return protocol_unsupported;
    return flags ? pts_failure : success;
  });
}
RESPONSECODE IFDHPowerICC(DWORD lun, DWORD action, PUCHAR atr, PDWORD length) {
  if (!length) return communication_error;
  const auto available = *length;
  *length = 0;
  return on_reader(lun, [&](Reader& reader) -> RESPONSECODE {
    if (action == 501) {
      (void)reader.ccid(0x63);
      reader.powered = false;
      reader.atr.clear();
      return success;
    }
    if (action != 500 && action != 502) return power_error;
    reader.atr = reader.ccid(0x62);
    if (reader.atr.empty() || reader.atr.size() > 33) return power_error;
    reader.powered = true;
    *length = available;
    return copy_output(reader.atr, atr, length);
  });
}
RESPONSECODE IFDHTransmitToICC(DWORD lun, SkeIfdPci send, PUCHAR input, DWORD size,
                             PUCHAR output, PDWORD length, SkeIfdPci* receive) {
  if (!length) return communication_error;
  const auto available = *length;
  *length = 0;
  if (receive) *receive = {};
  if (!input || !size || size > 65544 || !output) return communication_error;
  return on_reader(lun, [&](Reader& reader) -> RESPONSECODE {
    // IFD transmit PCI uses the protocol number, unlike SetProtocol's bitmask.
    if (send.Protocol != 1) return protocol_unsupported;
    if (!reader.powered) return absent;
    const auto response = reader.ccid(0x6f, {input, size});
    *length = available;
    const auto code = copy_output(response, output, length);
    if (code == success && receive) *receive = {1, sizeof(SkeIfdPci)};
    return code;
  });
}
RESPONSECODE IFDHControl(DWORD lun, DWORD control, PUCHAR, DWORD size, PUCHAR, DWORD, PDWORD returned) {
  if (!returned) return communication_error;
  *returned = 0;
  return on_reader(lun, [&](Reader&) -> RESPONSECODE {
    // PC/SC Part 10 feature request: no hardware PIN pad features are advertised.
    return control == 0x42000000 + 3400 && !size ? success : unsupported;
  });
}
RESPONSECODE IFDHICCPresence(DWORD lun) {
  return on_reader(lun, [&](Reader& reader) -> RESPONSECODE {
    const auto status = reader.ccid(0x65);
    return status[0] == 2 ? absent : present;
  });
}

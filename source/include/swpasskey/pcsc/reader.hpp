#pragma once

#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace swpk::pcsc {
struct WireError {
  int code;
};

// One persistent connection is one ISO 7816 card session. Power/reset explicitly
// clears that session; ordinary status queries preserve its authentication.
class Reader {
 public:
  explicit Reader(const std::string& socket_path);
  ~Reader();
  Reader(const Reader&) = delete;
  Reader& operator=(const Reader&) = delete;
  std::vector<std::uint8_t> ccid(std::uint8_t kind, std::span<const std::uint8_t> data = {});
  // Native composite transport forwards the existing framed service protocol.
  std::vector<std::uint8_t> exchange(std::span<const std::uint8_t> packet);
  void close();
  std::mutex mutex;
  std::vector<std::uint8_t> atr;
  std::string serial;
  bool powered{false};

 private:
  std::vector<std::uint8_t> ccid_part(std::uint8_t kind, std::span<const std::uint8_t> data, std::uint8_t level);
  void transfer(std::uint8_t* buffer, std::size_t length, bool writing);
  int fd_{-1};
  std::uint8_t sequence_{0};
};
}  // namespace swpk::pcsc

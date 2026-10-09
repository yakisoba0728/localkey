#include "swpasskey/hid/card_wire.hpp"
#include <array>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace swpk::hid {
namespace {
bool transfer(int fd, std::uint8_t* data, std::size_t size, bool writing) {
  while (size) {
#ifdef MSG_NOSIGNAL
    constexpr int flags = MSG_NOSIGNAL;
#else
    constexpr int flags = 0;
#endif
    const auto n = writing ? ::send(fd, data, size, flags) : ::recv(fd, data, size, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    data += n;
    size -= static_cast<std::size_t>(n);
  }
  return true;
}
struct Fd { int value; ~Fd() { ::close(value); } };
}

Result<std::vector<std::uint8_t>> card_command(
    const std::string& path, std::uint8_t command, std::span<const std::uint8_t> data) {
  struct stat info{};
  sockaddr_un address{};
  if (data.size() > 8192 || path.size() >= sizeof(address.sun_path) ||
      lstat(path.c_str(), &info) || !S_ISSOCK(info.st_mode) ||
      info.st_uid != geteuid() || (info.st_mode & 0077))
    return std::unexpected(Status::Other);
  Fd fd{::socket(AF_UNIX, SOCK_STREAM, 0)};
  if (fd.value < 0) return std::unexpected(Status::Other);
#ifdef SO_NOSIGPIPE
  int one = 1;
  (void)setsockopt(fd.value, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
  timeval timeout{2, 0};
  (void)setsockopt(fd.value, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  (void)setsockopt(fd.value, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
  if (connect(fd.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)))
    return std::unexpected(Status::Other);
  std::vector<std::uint8_t> packet;
  if (command == 0xff || command == 0xfe) {
    packet.resize(9); packet[0] = command == 0xff ? 4 : 9;
  } else {
    packet = {5, command, static_cast<std::uint8_t>(data.size() >> 8),
              static_cast<std::uint8_t>(data.size()), 0, 0, 0, 0, 0};
    packet.insert(packet.end(), data.begin(), data.end());
  }
  const auto size = packet.size();
  std::array<std::uint8_t, 4> prefix{0, 0, static_cast<std::uint8_t>(size >> 8),
                                  static_cast<std::uint8_t>(size)};
  if (!transfer(fd.value, prefix.data(), prefix.size(), true) ||
      !transfer(fd.value, packet.data(), packet.size(), true) ||
      !transfer(fd.value, prefix.data(), prefix.size(), false))
    return std::unexpected(Status::Other);
  const auto count = (std::uint32_t(prefix[0]) << 24) | (std::uint32_t(prefix[1]) << 16) |
                     (std::uint32_t(prefix[2]) << 8) | prefix[3];
  if (count > 8194) return std::unexpected(Status::Other);
  std::vector<std::uint8_t> response(count);
  if (!transfer(fd.value, response.data(), response.size(), false))
    return std::unexpected(Status::Other);
  if (command != 0xff && command != 0xfe) {
    if (response.size() < 2 || response[0] != 0x90 || response[1])
      return std::unexpected(Status::OperationDenied);
    response.erase(response.begin(), response.begin() + 2);
  }
  return response;
}
}

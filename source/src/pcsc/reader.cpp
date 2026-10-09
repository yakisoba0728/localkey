#include "swpasskey/pcsc/reader.hpp"
#include "swpasskey/usb/profile.hpp"

#include <array>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace swpk::pcsc {
namespace {
constexpr int communication_error = 612;
constexpr int response_timeout = 613;
constexpr int no_device = 617;
std::uint32_t read_le32(const std::uint8_t* value) {
  return std::uint32_t(value[0]) | (std::uint32_t(value[1]) << 8) |
         (std::uint32_t(value[2]) << 16) | (std::uint32_t(value[3]) << 24);
}
}  // namespace

Reader::Reader(const std::string& path) {
  sockaddr_un address{};
  struct stat info{};
  if (path.empty() || path.front() != '/' || path.size() >= sizeof(address.sun_path) ||
      lstat(path.c_str(), &info) || !S_ISSOCK(info.st_mode) ||
      info.st_uid != geteuid() || (info.st_mode & 0077))
    throw WireError{no_device};
  fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd_ < 0) throw WireError{communication_error};
  try {
#ifdef SO_NOSIGPIPE
    int one = 1;
    (void)setsockopt(fd_, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    timeval timeout{30, 0};
    (void)setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)))
      throw WireError{no_device};
#ifdef __APPLE__
    uid_t uid{};
    gid_t gid{};
    if (getpeereid(fd_, &uid, &gid) || uid != geteuid()) throw WireError{no_device};
#endif
    std::array<std::uint8_t, 9> request{};
    request[0] = 4;
    const auto identity = exchange(request);
    if (identity.size() != 7) throw WireError{communication_error};
    const auto number = (std::uint32_t(identity[3]) << 24) |
                        (std::uint32_t(identity[4]) << 16) |
                        (std::uint32_t(identity[5]) << 8) | identity[6];
    serial = std::to_string(number);
    (void)ccid(0x65);
  } catch (...) {
    close();
    throw;
  }
}
Reader::~Reader() { close(); }
void Reader::close() {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
  powered = false;
  atr.clear();
}
void Reader::transfer(std::uint8_t* data, std::size_t size, bool writing) {
  while (size) {
#ifdef MSG_NOSIGNAL
    constexpr int flags = MSG_NOSIGNAL;
#else
    constexpr int flags = 0;
#endif
    const auto count = writing ? ::send(fd_, data, size, flags) : ::recv(fd_, data, size, 0);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      const auto result = count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT)
                              ? response_timeout : no_device;
      close();
      throw WireError{result};
    }
    data += count;
    size -= static_cast<std::size_t>(count);
  }
}
std::vector<std::uint8_t> Reader::exchange(std::span<const std::uint8_t> request) {
  if (fd_ < 0) throw WireError{no_device};
  if (request.size() > 32786) throw WireError{communication_error};
  const auto size = request.size();
  std::array<std::uint8_t, 4> prefix{
      static_cast<std::uint8_t>(size >> 24), static_cast<std::uint8_t>(size >> 16),
      static_cast<std::uint8_t>(size >> 8), static_cast<std::uint8_t>(size)};
  transfer(prefix.data(), prefix.size(), true);
  // send() does not write to its input buffer.
  transfer(const_cast<std::uint8_t*>(request.data()), request.size(), true);
  transfer(prefix.data(), prefix.size(), false);
  const auto count = (std::uint32_t(prefix[0]) << 24) | (std::uint32_t(prefix[1]) << 16) |
                     (std::uint32_t(prefix[2]) << 8) | prefix[3];
  if (count > 32786) {
    close();
    throw WireError{communication_error};
  }
  std::vector<std::uint8_t> response(count);
  transfer(response.data(), response.size(), false);
  return response;
}
std::vector<std::uint8_t> Reader::ccid(std::uint8_t kind, std::span<const std::uint8_t> data) {
  if (data.size() > usb::kMaxCommandApduLength) throw WireError{communication_error};
  if (kind != 0x6f) {
    auto reply = ccid_part(kind, data, 0);
    if (kind == 0x65) return {static_cast<std::uint8_t>(reply[7] & 3)};
    return {reply.begin()+10, reply.end()};
  }
  const auto chunks = std::max<std::size_t>(1, (data.size()+usb::kCcidPayloadLength-1)/usb::kCcidPayloadLength);
  std::vector<std::uint8_t> response;
  std::uint8_t tail{};
  for (std::size_t i=0; i<chunks; ++i) {
    const auto offset = i*usb::kCcidPayloadLength;
    const auto count = std::min(usb::kCcidPayloadLength, data.size()-offset);
    const auto level = static_cast<std::uint8_t>(chunks == 1 ? 0 : i == 0 ? 1 : i+1 == chunks ? 2 : 3);
    auto part = ccid_part(kind, data.subspan(offset,count), level);
    tail = part[9];
    if (i+1 < chunks) {
      if (tail != 0x10 || part.size() != 10) { close(); throw WireError{communication_error}; }
    } else {
      if (tail != 0 && tail != 1) { close(); throw WireError{communication_error}; }
      response.insert(response.end(),part.begin()+10,part.end());
    }
  }
  while (tail == 1 || tail == 3) {
    auto part = ccid_part(kind, {}, 0x10);
    tail = part[9];
    if ((tail != 2 && tail != 3) || part.size() == 10 ||
        response.size()+part.size()-10 > usb::kMaxResponseApduLength) {
      close(); throw WireError{communication_error};
    }
    response.insert(response.end(),part.begin()+10,part.end());
  }
  return response;
}
std::vector<std::uint8_t> Reader::ccid_part(std::uint8_t kind, std::span<const std::uint8_t> data, std::uint8_t level) {
  if (data.size() > usb::kCcidPayloadLength) throw WireError{communication_error};
  const auto length = data.size();
  const auto sequence = ++sequence_;
  std::vector<std::uint8_t> packet{
      kind, static_cast<std::uint8_t>(length), static_cast<std::uint8_t>(length >> 8),
      static_cast<std::uint8_t>(length >> 16), static_cast<std::uint8_t>(length >> 24),
      0, sequence, 0, level, 0};
  packet.insert(packet.end(), data.begin(), data.end());
  auto reply = exchange(packet);
  const auto expected = kind == 0x62 || kind == 0x6f || kind == 0x69 ? 0x80 :
      kind == 0x61 || kind == 0x6c || kind == 0x6d ? 0x82 : kind == 0x6b ? 0x83 : kind == 0x73 ? 0x84 : 0x81;
  const auto valid_tail = reply.size() >= 10 && (expected == 0x80 ?
      reply[9] <= 3 || reply[9] == 0x10 : expected == 0x81 ? reply[9] <= 3 : expected == 0x82 ? reply[9] <= 1 : reply[9] == 0);
  if (reply.size() < 10 || reply.size() > usb::kCcidMessageLength || reply[0] != expected || read_le32(reply.data() + 1) != reply.size() - 10 ||
      reply[5] || reply[6] != sequence || !valid_tail || (reply[7] & 0xc0)) {
    close();
    throw WireError{communication_error};
  }
  return reply;
}
}  // namespace swpk::pcsc

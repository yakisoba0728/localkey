// Native Linux OTP feature reports and keyboard through the real UHID driver.
// Credentials and software button approval remain in the private card service.
#include "swpasskey/pcsc/reader.hpp"

#include <linux/input.h>
#include <linux/uhid.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
constexpr std::uint8_t descriptor[] = {
    0x05,0x01,0x09,0x06,0xa1,0x01,0x05,0x07,0x19,0xe0,0x29,0xe7,
    0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x08,0x81,0x02,
    0x95,0x01,0x75,0x08,0x81,0x01,0x95,0x05,0x75,0x01,0x05,0x08,
    0x19,0x01,0x29,0x05,0x91,0x02,0x95,0x01,0x75,0x03,0x91,0x01,
    0x95,0x06,0x75,0x08,0x15,0x00,0x25,0x65,0x05,0x07,0x19,0x00,
    0x29,0x65,0x81,0x00,0x06,0x00,0xff,0x09,0x01,0x75,0x08,
    0x95,0x08,0xb1,0x02,0xc0};

int hold_duration(const std::string& value) {
  int duration{};
  const auto result = std::from_chars(value.data(), value.data()+value.size(), duration);
  if (result.ec != std::errc{} || result.ptr != value.data()+value.size() ||
      duration < 0 || duration > 60000)
    throw std::invalid_argument("hold duration must be an integer from 0 through 60000 milliseconds");
  return duration;
}

std::array<std::uint8_t, 9> hold_packet(int duration) {
  std::array<std::uint8_t, 9> packet{};
  packet[0] = 6;
  packet[1] = static_cast<std::uint8_t>(duration >> 8);
  packet[2] = static_cast<std::uint8_t>(duration);
  return packet;
}

class Wire {
 public:
  explicit Wire(const std::string& path) : reader_(path) {}
  const std::string& serial() const { return reader_.serial; }
  std::vector<std::uint8_t> exchange(std::span<const std::uint8_t> packet) {
    std::lock_guard lock(reader_.mutex);
    return reader_.exchange(packet);
  }
  std::array<std::uint8_t, 8> feature(bool send, std::span<const std::uint8_t> report = {}) {
    std::array<std::uint8_t, 9> request{};
    request[0] = send ? 1 : 2;
    if (send) {
      if (report.size() != 8) throw std::invalid_argument("invalid OTP feature report");
      std::copy(report.begin(), report.end(), request.begin()+1);
    }
    const auto response = exchange(request);
    if (response.size() != 8) throw std::runtime_error("invalid OTP feature response");
    std::array<std::uint8_t, 8> result{};
    std::copy(response.begin(), response.end(), result.begin());
    return result;
  }
 private:
  swpk::pcsc::Reader reader_;
};

class Device {
 public:
  explicit Device(Wire& wire) : wire_(wire) {
    fd_ = ::open("/dev/uhid", O_RDWR | O_CLOEXEC);
    if (fd_ < 0) throw std::runtime_error("cannot open /dev/uhid");
    uhid_event event{};
    event.type = UHID_CREATE2;
    auto& cfg = event.u.create2;
    const auto copy_text = [](auto& buffer, const std::string& text) {
      const auto count = std::min(sizeof(buffer)-1, text.size());
      std::memcpy(buffer, text.data(), count);
    };
    copy_text(cfg.name, "Software OTP keyboard development device");
    copy_text(cfg.phys, "ske-otp");
    copy_text(cfg.uniq, wire.serial());
    cfg.rd_size = static_cast<__u16>(sizeof(descriptor));
    std::memcpy(cfg.rd_data, descriptor, sizeof(descriptor));
    cfg.bus = BUS_USB;
    cfg.vendor = 0x1209;
    cfg.product = 0xf055;
    cfg.version = 0x0400;
    if (!write_event(event)) {
      ::close(fd_);
      fd_ = -1;
      throw std::runtime_error("UHID_CREATE2 failed");
    }
    try {
      worker_ = std::jthread([this](std::stop_token stop) { serve(stop); });
    } catch (...) {
      ::close(fd_);
      fd_ = -1;
      throw;
    }
  }
  ~Device() {
    worker_.request_stop();
    if (worker_.joinable()) worker_.join();
    if (fd_ >= 0) {
      uhid_event release{};
      release.type = UHID_INPUT2;
      release.u.input2.size = 8;
      (void)write_event(release);
      uhid_event destroy{};
      destroy.type = UHID_DESTROY;
      (void)write_event(destroy);
      ::close(fd_);
    }
  }
  Device(const Device&) = delete;
  Device& operator=(const Device&) = delete;
  bool failed() const { return failed_.load(); }
  void input(std::span<const std::uint8_t, 8> report) {
    uhid_event event{};
    event.type = UHID_INPUT2;
    event.u.input2.size = 8;
    std::copy(report.begin(), report.end(), event.u.input2.data);
    if (!write_event(event)) throw std::runtime_error("keyboard report injection failed");
  }
 private:
  bool write_event(const uhid_event& event) {
    std::lock_guard lock(write_mutex_);
    ssize_t count;
    do { count = ::write(fd_, &event, sizeof(event)); }
    while (count < 0 && errno == EINTR);
    return count == static_cast<ssize_t>(sizeof(event));
  }
  void get_report(const uhid_get_report_req& request) {
    uhid_event reply{};
    reply.type = UHID_GET_REPORT_REPLY;
    reply.u.get_report_reply.id = request.id;
    reply.u.get_report_reply.err = EOPNOTSUPP;
    if (request.rtype == UHID_FEATURE_REPORT && request.rnum == 0) {
      try {
        const auto report = wire_.feature(false);
        // hidraw feature ioctls carry the report number, including zero.
        reply.u.get_report_reply.size = 9;
        std::copy(report.begin(), report.end(), reply.u.get_report_reply.data+1);
        reply.u.get_report_reply.err = 0;
      } catch (...) { reply.u.get_report_reply.err = EIO; }
    }
    if (!write_event(reply)) failed_.store(true);
  }
  void set_report(const uhid_set_report_req& request) {
    if (std::getenv("SKE_TRACE_UHID"))
      std::cerr << "SET_REPORT type=" << unsigned(request.rtype)
                << " number=" << unsigned(request.rnum) << " size=" << request.size << '\n';
    uhid_event reply{};
    reply.type = UHID_SET_REPORT_REPLY;
    reply.u.set_report_reply.id = request.id;
    reply.u.set_report_reply.err = EOPNOTSUPP;
    if (request.rtype == UHID_OUTPUT_REPORT && request.rnum == 0 && request.size == 1) {
      reply.u.set_report_reply.err = 0;  // Keyboard LED state is accepted.
    } else if (request.rtype == UHID_FEATURE_REPORT && request.rnum == 0) {
      std::span<const std::uint8_t> data(request.data, request.size);
      if (data.size() == 9 && data.front() == 0) data = data.subspan(1);
      if (data.size() != 8) reply.u.set_report_reply.err = EINVAL;
      else {
        try { (void)wire_.feature(true, data); reply.u.set_report_reply.err = 0; }
        catch (...) { reply.u.set_report_reply.err = EIO; }
      }
    }
    if (!write_event(reply)) failed_.store(true);
  }
  void serve(std::stop_token stop) {
    while (!stop.stop_requested() && !failed()) {
      pollfd descriptor_fd{fd_, POLLIN, 0};
      const auto result = ::poll(&descriptor_fd, 1, 100);
      if (result < 0 && errno == EINTR) continue;
      if (result < 0 || (descriptor_fd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
        failed_.store(true); break;
      }
      if (!result) continue;
      uhid_event event{};
      const auto count = ::read(fd_, &event, sizeof(event));
      if (count < 0 && errno == EINTR) continue;
      if (count < static_cast<ssize_t>(sizeof(event.type))) {
        failed_.store(true); break;
      }
      switch (event.type) {
        case UHID_GET_REPORT: get_report(event.u.get_report); break;
        case UHID_SET_REPORT: set_report(event.u.set_report); break;
        case UHID_OUTPUT: break;  // Keyboard LED output; no OTP feature payload.
        default: break;  // START/OPEN/CLOSE/STOP are kernel lifecycle notices.
      }
    }
  }
  Wire& wire_;
  int fd_{-1};
  std::mutex write_mutex_;
  std::atomic<bool> failed_{false};
  std::jthread worker_;
};

std::string hex(std::span<const std::uint8_t> value) {
  constexpr char alphabet[] = "0123456789abcdef";
  std::string result;
  for (const auto byte : value) {
    result += alphabet[byte >> 4]; result += alphabet[byte & 15];
  }
  return result;
}

void type_response(Device& device, std::span<const std::uint8_t> response) {
  if (response.size() < 4 || response[0] != 0x90 || response[1] != 0)
    throw std::runtime_error("card rejected the software button request");
  const auto count = (std::size_t(response[2]) << 8) | response[3];
  if (response.size() != 4+count*10) throw std::runtime_error("invalid keyboard event frame");
  for (std::size_t offset=4; offset<response.size(); offset+=10) {
    device.input(std::span<const std::uint8_t,8>(response.data()+offset, 8));
    const auto delay = (unsigned(response[offset+8]) << 8) | response[offset+9];
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
  }
}
}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--help") {
    std::cout << "ske-otpd --socket PATH\n"
                 "Creates a Linux UHID OTP feature/keyboard device.\n"
                 "Enter 1 or 2 for a software slot press, hold N for a hold/release in milliseconds, or quit.\n"
                 "The card service confirms user presence.\n"
                 "ske-otpd --wire-test PATH [--hold-ms N] tests the private wire protocol.\n";
    return 0;
  }
  const bool wire_test = argc >= 3 && std::string(argv[1]) == "--wire-test";
  if ((argc != 3 && !(argc == 5 && wire_test && std::string(argv[3]) == "--hold-ms")) ||
      (!wire_test && std::string(argv[1]) != "--socket")) {
    std::cerr << "usage: ske-otpd --socket PATH | --wire-test PATH [--hold-ms N]\n";
    return 2;
  }
  try {
    const auto test_hold = argc == 5 ? hold_duration(argv[4]) : -1;
    Wire wire(argv[2]);
    if (wire_test) {
      const auto status = wire.feature(false);
      std::array<std::uint8_t,9> packet{};
      packet[0] = 3; packet[1] = 1;
      if (test_hold >= 0) packet = hold_packet(test_hold);
      const auto response = wire.exchange(packet);
      std::cout << "{\"serial\":" << wire.serial() << ",\"status\":\"" << hex(status)
                << "\",\"keyboard_events\":\"" << hex(response) << "\"}\n";
      return 0;
    }
    Device device(wire);
    std::cout << "OTP HID active. Enter 1 or 2, hold N (milliseconds), or quit.\n" << std::flush;
    while (!device.failed()) {
      pollfd input{STDIN_FILENO, POLLIN, 0};
      const auto result = ::poll(&input, 1, 100);
      if (result < 0 && errno == EINTR) continue;
      if (result < 0 || (input.revents & (POLLERR | POLLNVAL)))
        throw std::runtime_error("stdin polling failed");
      if (!result) continue;
      std::string line;
      if (!std::getline(std::cin, line) || line == "quit") break;
      std::array<std::uint8_t,9> packet{};
      if (line == "1" || line == "2") {
        packet[0] = 3; packet[1] = static_cast<std::uint8_t>(line[0]-'0');
      } else if (line.starts_with("hold ")) {
        try { packet = hold_packet(hold_duration(line.substr(5))); }
        catch (const std::invalid_argument& error) { std::cerr << error.what() << '\n'; continue; }
      } else continue;
      type_response(device, wire.exchange(packet));
    }
    if (device.failed()) throw std::runtime_error("UHID transport stopped");
    return 0;
  } catch (const swpk::pcsc::WireError& error) {
    std::cerr << "private card service failed (" << error.code << ")\n";
    return 1;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}

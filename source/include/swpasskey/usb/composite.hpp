#pragma once

#include <array>
#include <cstdint>
#include <chrono>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace swpk::usb {
using Bytes = std::vector<std::uint8_t>;
struct Setup {
  std::uint8_t type{}, request{};
  std::uint16_t value{}, index{}, length{};
  static Setup decode(std::span<const std::uint8_t> bytes);
};
struct ControlResult { bool stalled{false}; Bytes data; };
enum class Interface { Otp, Fido, Ccid };

// USB Chapter 9, HID and CCID routing for one software composite device.
// Callers serialize access and own asynchronous IO, buffering and lifecycle.
class Composite {
 public:
  using Rpc = std::function<Bytes(std::span<const std::uint8_t>)>;
  Composite(std::string serial, std::uint16_t applications, Rpc card_rpc, bool compatibility_ids = false);
  ControlResult control(Setup setup, std::span<const std::uint8_t> output = {});
  bool output(std::uint8_t endpoint, std::span<const std::uint8_t> data);
  std::optional<Bytes> input(std::uint8_t endpoint, std::size_t capacity);
  bool input_queue_full(std::uint8_t endpoint) const;
  void queue_input(std::uint8_t endpoint, Bytes data);
  std::vector<Bytes> take_fido_output();
  std::vector<Bytes> take_ccid_output();
  void reset();
  void poll_keyboard_idle();
  Bytes device_descriptor() const;
  Bytes configuration_descriptor() const;
  Bytes report_descriptor(std::size_t interface) const;
  bool endpoint_exists(std::uint8_t endpoint) const;
  bool endpoint_halted(std::uint8_t endpoint) const;
  bool replies_pending() const;
  std::optional<Interface> interface_kind(std::size_t index) const;
  bool configured() const { return configuration_ == 1; }
  std::size_t interface_count() const { return interfaces_.size(); }

 private:
  std::string serial_;
  bool compatibility_ids_;
  std::vector<Interface> interfaces_;
  Rpc card_rpc_;
  std::uint8_t configuration_{0}, address_{0};
  std::map<std::uint8_t, bool> halted_;
  std::array<std::uint8_t, 3> idle_{};
  std::uint8_t keyboard_protocol_{1}, keyboard_leds_{0};
  std::array<std::uint8_t,8> keyboard_report_{};
  std::chrono::steady_clock::time_point keyboard_sent_{std::chrono::steady_clock::now()};
  std::map<std::uint8_t, std::deque<Bytes>> inputs_;
  Bytes ccid_partial_;
  std::vector<Bytes> fido_output_, ccid_output_;
};
}  // namespace swpk::usb

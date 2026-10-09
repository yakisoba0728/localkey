#include "swpasskey/usb/composite.hpp"
#include "swpasskey/constants.hpp"
#include "swpasskey/usb/profile.hpp"

#include <algorithm>
#include <stdexcept>

namespace swpk::usb {
namespace {
std::uint16_t le16(const std::uint8_t* p) {
  return std::uint16_t(p[0]) | static_cast<std::uint16_t>(std::uint16_t(p[1]) << 8);
}
std::uint32_t le32(const std::uint8_t* p) {
  return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) |
      (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}
void append(Bytes& to, std::initializer_list<std::uint8_t> data) {
  to.insert(to.end(), data);
}
Bytes string_descriptor(const std::string& text) {
  if (text.size() > 126 || std::ranges::any_of(text, [](auto c) { return c < 0 || c > 127; }))
    throw std::invalid_argument("USB identity must be short ASCII");
  Bytes result{static_cast<std::uint8_t>(2 + text.size() * 2), 3};
  for (const auto c : text) append(result, {static_cast<std::uint8_t>(c), 0});
  return result;
}
constexpr std::uint8_t fido_report[] = {
    0x06,0xd0,0xf1,0x09,0x01,0xa1,0x01,0x09,0x20,0x15,0x00,0x26,0xff,0x00,
    0x75,0x08,0x95,0x40,0x81,0x02,0x09,0x21,0x15,0x00,0x26,0xff,0x00,
    0x75,0x08,0x95,0x40,0x91,0x02,0xc0};
constexpr std::uint8_t otp_report[] = {
    0x05,0x01,0x09,0x06,0xa1,0x01,0x05,0x07,0x19,0xe0,0x29,0xe7,
    0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x08,0x81,0x02,
    0x95,0x01,0x75,0x08,0x81,0x01,0x95,0x05,0x75,0x01,0x05,0x08,
    0x19,0x01,0x29,0x05,0x91,0x02,0x95,0x01,0x75,0x03,0x91,0x01,
    0x95,0x06,0x75,0x08,0x15,0x00,0x25,0x65,0x05,0x07,0x19,0x00,
    0x29,0x65,0x81,0x00,0x06,0x00,0xff,0x09,0x01,0x75,0x08,
    0x95,0x08,0xb1,0x02,0xc0};
constexpr std::size_t kInputQueueCapacity = 256;
}  // namespace

Setup Setup::decode(std::span<const std::uint8_t> data) {
  if (data.size() != 8) throw std::invalid_argument("USB SETUP must be eight bytes");
  return {data[0], data[1], le16(data.data() + 2), le16(data.data() + 4), le16(data.data() + 6)};
}
Composite::Composite(std::string serial, std::uint16_t applications, Rpc rpc, bool compatibility_ids)
    : serial_(std::move(serial)), compatibility_ids_(compatibility_ids), card_rpc_(std::move(rpc)) {
  (void)string_descriptor(serial_);
  if (applications & 0x0001) interfaces_.push_back(Interface::Otp);
  if (applications & 0x0202) interfaces_.push_back(Interface::Fido);
  if (applications & 0x0138) interfaces_.push_back(Interface::Ccid);
  if (interfaces_.empty()) throw std::invalid_argument("no enabled USB interfaces");
}
std::optional<Interface> Composite::interface_kind(std::size_t index) const {
  if (index >= interfaces_.size()) return std::nullopt;
  return interfaces_[index];
}
bool Composite::replies_pending() const {
  for (const auto address : {kCcidIn, kFidoIn}) {
    const auto found = inputs_.find(address);
    if (found != inputs_.end() && !found->second.empty()) return true;
  }
  return !ccid_output_.empty() || !fido_output_.empty();
}
Bytes Composite::device_descriptor() const {
  // Experimental VID/PID, independent software identity, USB 2.0 full speed.
  auto vid = kUsbVid, pid = kUsbPid;
  if (compatibility_ids_) {
    // Public SDK matching IDs only. Keys, serial, AAGUID and attestation remain
    // independent; these descriptor values confer no manufacturer trust.
    vid = 0x1050; pid = 0x0400;
    for (const auto kind : interfaces_) {
      pid = static_cast<std::uint16_t>(pid | (kind == Interface::Otp ? 1 : kind == Interface::Fido ? 2 : 4));
    }
  }
  return {18,1,0x00,0x02,0,0,0,64,
      static_cast<std::uint8_t>(vid),static_cast<std::uint8_t>(vid >> 8),
      static_cast<std::uint8_t>(pid),static_cast<std::uint8_t>(pid >> 8),
      0x74,0x05,1,2,3,1};
}
Bytes Composite::report_descriptor(std::size_t index) const {
  const auto kind = interface_kind(index);
  if (kind == Interface::Otp) return {std::begin(otp_report), std::end(otp_report)};
  if (kind == Interface::Fido) return {std::begin(fido_report), std::end(fido_report)};
  return {};
}
Bytes Composite::configuration_descriptor() const {
  Bytes data{9,2,0,0,static_cast<std::uint8_t>(interfaces_.size()),1,0,0x80,15};
  for (std::size_t i = 0; i < interfaces_.size(); ++i) {
    const auto index = static_cast<std::uint8_t>(i);
    const auto kind = interfaces_[i];
    if (kind == Interface::Ccid) {
      append(data, {9,4,index,0,3,0x0b,0,0,0});
      // One T=1 slot, extended-APDU exchange, automatic clock/baud/parameters.
      append(data, {54,0x21,0x00,0x01,0,7,2,0,0,0,
                    0xa0,0x0f,0,0,0xa0,0x0f,0,0,0,
                    0x00,0xb0,4,0,0x00,0xb0,4,0,0,
                    0xf6,0x0b,0,0,0,0,0,0,0,0,0,0,
                    0xfe,0,4,0,0x00,0x0c,0,0,0xff,0xff,0,0,0,1});
      append(data, {7,5,kCcidOut,2,64,0,0, 7,5,kCcidIn,2,64,0,0, 7,5,kCcidInterrupt,3,8,0,32});
    } else {
      const auto otp = kind == Interface::Otp;
      append(data, {9,4,index,0,static_cast<std::uint8_t>(otp ? 1 : 2),3,
                    static_cast<std::uint8_t>(otp ? 1 : 0),static_cast<std::uint8_t>(otp ? 1 : 0),0});
      const auto report = report_descriptor(i);
      append(data, {9,0x21,0x10,0x01,0,1,0x22,static_cast<std::uint8_t>(report.size()),0});
      if (otp) append(data, {7,5,0x81,3,8,0,10});
      else append(data, {7,5,kFidoOut,3,64,0,2, 7,5,kFidoIn,3,64,0,2});
    }
  }
  data[2] = static_cast<std::uint8_t>(data.size());
  data[3] = static_cast<std::uint8_t>(data.size() >> 8);
  return data;
}
bool Composite::endpoint_exists(std::uint8_t ep) const {
  for (const auto kind : interfaces_) {
    if (kind == Interface::Otp && ep == 0x81) return true;
    if (kind == Interface::Fido && (ep == kFidoOut || ep == kFidoIn)) return true;
    if (kind == Interface::Ccid && (ep == kCcidOut || ep == kCcidIn || ep == kCcidInterrupt)) return true;
  }
  return ep == 0 || ep == 0x80;
}
bool Composite::endpoint_halted(std::uint8_t ep) const {
  const auto found = halted_.find(ep);
  return found != halted_.end() && found->second;
}
void Composite::reset() {
  configuration_ = address_ = 0;
  keyboard_protocol_ = 1;
  keyboard_leds_ = 0;
  keyboard_report_.fill(0);
  keyboard_sent_ = std::chrono::steady_clock::now();
  idle_.fill(0);
  halted_.clear(); inputs_.clear(); ccid_partial_.clear();
  fido_output_.clear(); ccid_output_.clear();
}
ControlResult Composite::control(Setup q, std::span<const std::uint8_t> output) {
  ControlResult result;
  const auto stall = [] { return ControlResult{true, {}}; };
  const bool in = q.type & 0x80;
  if ((in && !output.empty()) || (!in && output.size() != q.length)) return stall();
  const auto recipient = q.type & 0x1f;
  const auto kind = interface_kind(q.index);
  if ((q.type & 0x60) == 0) {
    switch (q.request) {
      case 6: {
        if (!in) return stall();
        const auto type = q.value >> 8, index = q.value & 0xff;
        if (recipient == 0 && type == 1 && !index && !q.index) result.data = device_descriptor();
        else if (recipient == 0 && type == 2 && !index && !q.index) result.data = configuration_descriptor();
        else if (recipient == 0 && type == 3) {
          if (!index && !q.index) result.data = {4,3,0x09,0x04};
          else if (q.index == 0x0409) {
            if (index == 1) result.data = string_descriptor("Local software authenticator");
            else if (index == 2) {
              std::string label = compatibility_ids_ ? "Yubico YubiKey compatible software" : "Software authenticator";
              for (const auto iface : interfaces_)
                label += iface == Interface::Otp ? " OTP" : iface == Interface::Fido ? " FIDO" : " CCID";
              result.data = string_descriptor(label);
            }
            else if (index == 3) result.data = string_descriptor(serial_);
            else return stall();
          } else return stall();
        } else if (recipient == 1 && kind && (type == 0x21 || type == 0x22) && !index) {
          if (*kind == Interface::Ccid) return stall();
          result.data = report_descriptor(q.index);
          if (type == 0x21) result.data = {9,0x21,0x10,0x01,0,1,0x22,static_cast<std::uint8_t>(result.data.size()),0};
        } else return stall();
        break;
      }
      case 5:
        if (q.type != 0 || q.index || q.length || q.value > 127 || configured()) return stall();
        address_ = static_cast<std::uint8_t>(q.value); break;
      case 8:
        if (q.type != 0x80 || q.value || q.index || q.length != 1) return stall();
        result.data = {configuration_}; break;
      case 9:
        if (q.type != 0 || q.index || q.length || q.value > 1) return stall();
        configuration_ = static_cast<std::uint8_t>(q.value);
        inputs_.clear(); ccid_partial_.clear(); halted_.clear();
        if (configured() && endpoint_exists(kCcidInterrupt)) queue_input(kCcidInterrupt, {0x50,0x03});
        break;
      case 0:
        if (!in || q.value || q.length != 2) return stall();
        if (recipient == 0 && !q.index) result.data = {0,0};
        else if (recipient == 1 && configured() && kind) result.data = {0,0};
        else if (recipient == 2 && q.index <= 255 && endpoint_exists(static_cast<std::uint8_t>(q.index)))
          result.data = {static_cast<std::uint8_t>(halted_[static_cast<std::uint8_t>(q.index)]),0};
        else return stall();
        break;
      case 1: case 3:
        if (q.type != 2 || q.value || q.length || !configured() || q.index > 255 ||
            !(q.index & 0x0f) || !endpoint_exists(static_cast<std::uint8_t>(q.index))) return stall();
        halted_[static_cast<std::uint8_t>(q.index)] = q.request == 3; break;
      case 10:
        if (q.type != 0x81 || q.value || q.length != 1 || !configured() || !kind) return stall();
        result.data = {0}; break;
      case 11:
        if (q.type != 1 || q.value || q.length || !configured() || !kind) return stall();
        break;
      default: return stall();
    }
  } else if ((q.type & 0x60) == 0x20 && recipient == 1 && configured() && kind) {
    if (*kind == Interface::Ccid) {
      if (q.request == 1 && q.type == 0x21 && !q.length && !(q.value & 0xff)) {
        const std::array<std::uint8_t,3> packet{7,0,static_cast<std::uint8_t>(q.value >> 8)};
        const auto response = card_rpc_(packet);
        if (response != Bytes{0x90,0}) return stall();
      } else {
        if (q.type != 0xa1 || q.value) return stall();
        if (q.request == 2) result.data = {0xa0,0x0f,0,0};
        else if (q.request == 3) result.data = {0x00,0xb0,4,0};
        else return stall();
      }
    } else {
      const auto report_type = q.value >> 8, report_id = q.value & 0xff;
      if (report_id) return stall();
      if (q.request == 1 && q.type == 0xa1) {
        if (*kind == Interface::Otp && report_type == 3 && q.length == 8) {
          std::array<std::uint8_t,9> packet{}; packet[0] = 2;
          result.data = card_rpc_(packet);
          if (result.data.size() != 8) throw std::runtime_error("invalid OTP feature response");
        } else if (*kind == Interface::Otp && report_type == 1 && q.length == 8)
          result.data.assign(keyboard_report_.begin(), keyboard_report_.end());
        else if (*kind == Interface::Otp && report_type == 2 && q.length == 1) result.data = {keyboard_leds_};
        else return stall();
      } else if (q.request == 9 && q.type == 0x21) {
        if (*kind == Interface::Otp && report_type == 3 && q.length == 8) {
          Bytes packet{1}; packet.insert(packet.end(), output.begin(), output.end());
          const auto response = card_rpc_(packet);
          if (response.size() != 8) throw std::runtime_error("invalid OTP feature response");
        } else if (*kind == Interface::Otp && report_type == 2 && q.length == 1) keyboard_leds_ = output[0] & 31;
        else if (*kind == Interface::Fido && report_type == 2 && q.length == 64) {
          fido_output_.emplace_back(output.begin(), output.end());
        } else return stall();
      } else if (q.request == 2 && q.type == 0xa1 && !q.value && q.length == 1) result.data = {idle_[q.index]};
      else if (q.request == 10 && q.type == 0x21 && !q.length) idle_[q.index] = static_cast<std::uint8_t>(q.value >> 8);
      else if (*kind == Interface::Otp && q.request == 3 && q.type == 0xa1 && !q.value && q.length == 1) result.data = {keyboard_protocol_};
      else if (*kind == Interface::Otp && q.request == 11 && q.type == 0x21 && q.value <= 1 && !q.length)
        keyboard_protocol_ = static_cast<std::uint8_t>(q.value);
      else return stall();
    }
  } else return stall();
  if (in && result.data.size() > q.length) result.data.resize(q.length);
  return result;
}
bool Composite::output(std::uint8_t ep, std::span<const std::uint8_t> data) {
  if (!configured() || halted_[ep] || !endpoint_exists(ep)) return false;
  if (ep == kFidoOut) {
    if (data.size() != 64 || fido_output_.size() >= 32) return false;
    fido_output_.emplace_back(data.begin(), data.end()); return true;
  }
  if (ep != kCcidOut || ccid_output_.size() >= 32 || data.size() > kCcidMessageLength || ccid_partial_.size() + data.size() > kCcidMessageLength)
    return false;
  ccid_partial_.insert(ccid_partial_.end(), data.begin(), data.end());
  if (ccid_partial_.size() >= 10) {
    const auto length = le32(ccid_partial_.data() + 1);
    if (length > kCcidPayloadLength || ccid_partial_.size() > length + 10) {
      ccid_partial_.clear(); return false;
    }
    if (ccid_partial_.size() == length + 10) {
      ccid_output_.push_back(std::move(ccid_partial_)); ccid_partial_.clear();
    }
  }
  return true;
}
bool Composite::input_queue_full(std::uint8_t ep) const {
  const auto found = inputs_.find(ep);
  return found != inputs_.end() && found->second.size() >= kInputQueueCapacity;
}
void Composite::queue_input(std::uint8_t ep, Bytes data) {
  if (!configured() || !(ep & 0x80) || !endpoint_exists(ep)) return;
  const auto limit = ep == kCcidIn ? kCcidMessageLength : ep == kFidoIn ? 64U : 8U;
  if (data.size() > limit || input_queue_full(ep)) throw std::runtime_error("USB input queue overflow");
  inputs_[ep].push_back(std::move(data));
}
std::optional<Bytes> Composite::input(std::uint8_t ep, std::size_t capacity) {
  if (!configured() || halted_[ep] || !endpoint_exists(ep) || !(ep & 0x80)) return std::nullopt;
  auto& queue = inputs_[ep];
  if (queue.empty() || !capacity) return std::nullopt;
  auto& front = queue.front();
  // HID and slot-change messages must stay whole; CCID bulk may be segmented.
  if (ep != kCcidIn && front.size() > capacity) throw std::invalid_argument("USB input buffer too small");
  const auto count = std::min(front.size(), capacity);
  Bytes result(front.begin(), front.begin() + static_cast<std::ptrdiff_t>(count));
  if (ep == 0x81 && result.size() == 8) {
    std::copy(result.begin(), result.end(), keyboard_report_.begin());
    keyboard_sent_ = std::chrono::steady_clock::now();
  }
  front.erase(front.begin(), front.begin() + static_cast<std::ptrdiff_t>(count));
  if (front.empty()) queue.pop_front();
  return result;
}
void Composite::poll_keyboard_idle() {
  for (std::size_t i = 0; i < interfaces_.size(); ++i) {
    if (interfaces_[i] != Interface::Otp || !idle_[i] || !configured() || !inputs_[0x81].empty()) continue;
    if (std::chrono::steady_clock::now() - keyboard_sent_ >= std::chrono::milliseconds(4 * idle_[i]))
      queue_input(0x81, {keyboard_report_.begin(), keyboard_report_.end()});
  }
}
std::vector<Bytes> Composite::take_fido_output() {
  std::vector<Bytes> out; out.swap(fido_output_); return out;
}
std::vector<Bytes> Composite::take_ccid_output() {
  std::vector<Bytes> out; out.swap(ccid_output_); return out;
}
}  // namespace swpk::usb

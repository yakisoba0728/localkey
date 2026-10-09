#pragma once
// Shared composite protocol backend for the macOS and Linux USB transports.
#include "swpasskey/pcsc/reader.hpp"
#include "swpasskey/usb/composite.hpp"
#include "swpasskey/usb/profile.hpp"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
namespace swpk::usb::native {
std::string hex(std::span<const std::uint8_t> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (auto byte : bytes) { out += digits[byte >> 4]; out += digits[byte & 15]; }
  return out;
}
Bytes unhex(const std::string& input) {
  if (input.size() % 2) throw std::invalid_argument("odd hex length");
  Bytes out;
  auto digit = [](char c) -> std::uint8_t {
    if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
    throw std::invalid_argument("invalid hex");
  };
  for (std::size_t i = 0; i < input.size(); i += 2)
    out.push_back(static_cast<std::uint8_t>((digit(input[i]) << 4) | digit(input[i+1])));
  return out;
}
class FidoWire {
 public:
  explicit FidoWire(const std::string& path) {
    sockaddr_un address{};
    struct stat info{};
    if (path.empty() || path.front() != '/' || path.size() >= sizeof(address.sun_path) ||
        lstat(path.c_str(), &info) || !S_ISSOCK(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & 0077))
      throw std::runtime_error("FIDO socket must be private and owned by this user");
    fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_ < 0) throw std::runtime_error("FIDO socket creation failed");
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    timeval timeout{30,0};
    setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    if (connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address))) {
      ::close(fd_); fd_ = -1;
      throw std::runtime_error("FIDO daemon unavailable");
    }
#ifdef __APPLE__
    uid_t uid{}; gid_t gid{};
    const bool trusted = !getpeereid(fd_, &uid, &gid) && uid == geteuid();
#else
    ucred peer{}; socklen_t peer_size = sizeof(peer);
    const bool trusted = !getsockopt(fd_, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size)
        && peer_size == sizeof(peer) && peer.uid == geteuid();
#endif
    if (!trusted) {
      ::close(fd_); fd_ = -1; throw std::runtime_error("unexpected FIDO peer");
    }
  }
  ~FidoWire() { if (fd_ >= 0) ::close(fd_); }
  void write(std::span<const std::uint8_t> data) {
    if (data.size() != 64) throw std::runtime_error("invalid FIDO HID report");
    while (!data.empty()) {
#ifdef MSG_NOSIGNAL
      constexpr int flags = MSG_NOSIGNAL;
#else
      constexpr int flags = 0;
#endif
      const auto count = send(fd_, data.data(), data.size(), flags);
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) throw std::runtime_error("FIDO daemon disconnected");
      data = data.subspan(static_cast<std::size_t>(count));
    }
  }
  std::optional<Bytes> read_one() {
    for (;;) {
      std::array<std::uint8_t,64> packet{};
      const auto count = recv(fd_, packet.data(), packet.size() - partial_.size(), MSG_DONTWAIT);
      if (count < 0 && errno == EINTR) continue;
      if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return std::nullopt;
      if (count <= 0) throw std::runtime_error("FIDO daemon disconnected");
      partial_.insert(partial_.end(), packet.begin(), packet.begin() + count);
      if (partial_.size() == 64) {
        Bytes result;
        result.swap(partial_);
        return result;
      }
    }
  }
 private:
  int fd_{-1};
  Bytes partial_;
};

struct Backend {
  swpk::pcsc::Reader card;
  swpk::pcsc::Reader auxiliary;
  std::unique_ptr<FidoWire> fido;
  std::string fido_path_;
  std::unique_ptr<Composite> model;
  std::deque<std::pair<Bytes,std::chrono::steady_clock::time_point>> keyboard;
  std::chrono::steady_clock::time_point next_keyboard_poll_{};
  struct Job { Bytes packet; std::uint64_t generation; bool visible{true}; };
  std::array<std::uint8_t,16> session_token_{};
  std::mutex ccid_mutex_;
  std::condition_variable ccid_condition_;
  std::deque<Job> ccid_jobs_;
  std::deque<Bytes> ccid_ready_;
  std::thread ccid_worker_;
  std::optional<std::uint8_t> abort_sequence_;
  std::uint64_t ccid_generation_{};
  std::uint64_t active_generation_{};
  std::chrono::steady_clock::time_point next_wtx_;
  std::uint8_t icc_status_{1}, clock_status_{3}, active_kind_{}, active_sequence_{};
  bool ccid_active_{false}, ccid_stopping_{false}, ccid_failed_{false};
  struct UsbState { std::uint64_t generation{}; std::uint16_t applications{}; };
  UsbState usb_state_{};
  std::optional<UsbState> pending_usb_state_;
  std::chrono::steady_clock::time_point next_usb_poll_, reboot_requested_at_;
  bool compatibility_ids_{};
  bool usb_suspended_{};
  Backend(const std::string& card_path, const std::string& fido_path, bool compatibility_ids)
      : card(card_path), auxiliary(card_path), fido(std::make_unique<FidoWire>(fido_path)),
        fido_path_(fido_path), compatibility_ids_(compatibility_ids) {
    std::array<std::uint8_t,9> identity{}; identity[0] = 8;
    const auto token = card.exchange(identity);
    if (token.size() != 17 || token[0] != 1)
      throw std::runtime_error("invalid CCID session token");
    std::copy(token.begin()+1, token.end(), session_token_.begin());
    usb_state_ = read_usb_state();
    rebuild_model(usb_state_.applications);
    ccid_worker_ = std::thread([this] { run_ccid(); });
  }
  UsbState read_usb_state() {
    std::array<std::uint8_t,9> request{}; request[0] = 9;
    const auto response = auxiliary.exchange(request);
    if (response.size() != 11 || response[0] != 1)
      throw std::runtime_error("invalid USB lifecycle response");
    UsbState value;
    for (std::size_t i = 1; i < 9; ++i) value.generation = (value.generation << 8) | response[i];
    value.applications = static_cast<std::uint16_t>((std::uint16_t(response[9]) << 8) | response[10]);
    return value;
  }
  void rebuild_model(std::uint16_t applications) {
    model = std::make_unique<Composite>(card.serial, applications,
        [this](auto data) {
          if (data.size() == 3 && data[0] == 7) return abort_rpc(data[1], data[2]);
          return auxiliary.exchange(data);
        }, compatibility_ids_);
  }
  bool poll_reboot() {
    const auto now = std::chrono::steady_clock::now();
    if (now >= next_usb_poll_) {
      const auto value = read_usb_state();
      next_usb_poll_ = now + std::chrono::milliseconds(20);
      if (value.generation != usb_state_.generation) {
        if (!pending_usb_state_) reboot_requested_at_ = now;
        pending_usb_state_ = value;
      }
    }
    return pending_usb_state_.has_value();
  }
  bool reboot_ready(bool endpoint_reply_pending) {
    if (!pending_usb_state_) return false;
    const auto elapsed = std::chrono::steady_clock::now() - reboot_requested_at_;
    // A modeled response grace period, not a measured firmware reboot delay.
    // A host that stops reading must not indefinitely prevent a committed reboot.
    if (elapsed >= std::chrono::seconds(2)) return true;
    if (elapsed < std::chrono::milliseconds(100) || endpoint_reply_pending || model->replies_pending()) return false;
    std::lock_guard guard(ccid_mutex_);
    return !ccid_active_ && ccid_jobs_.empty() && ccid_ready_.empty();
  }
  void apply_reboot() {
    if (!pending_usb_state_) return;
    const auto value = *pending_usb_state_;
    reset();
    rebuild_model(value.applications);
    usb_state_ = value;
    pending_usb_state_.reset();
  }
  ~Backend() {
    bool pending; std::uint8_t sequence;
    {
      std::lock_guard guard(ccid_mutex_);
      pending = ccid_active_;
      sequence = active_kind_ == 0x72 ? active_sequence_ : 255;
      ccid_stopping_ = true;
    }
    ccid_condition_.notify_all();
    if (pending) { try { (void)abort_rpc(0, sequence); } catch (...) {} }
    if (ccid_worker_.joinable()) ccid_worker_.join();
  }
  Bytes abort_rpc(std::uint8_t slot, std::uint8_t sequence) {
    Bytes request{7};
    request.insert(request.end(), session_token_.begin(), session_token_.end());
    request.push_back(slot); request.push_back(sequence);
    std::optional<std::uint8_t> previous;
    if (!slot) {
      // A pending bulk-first ABORT can finish as soon as its control RPC is
      // delivered. Publish the barrier before delivery so completion cannot
      // clear it and then have this thread restore an already-finished pair.
      std::lock_guard guard(ccid_mutex_);
      previous = abort_sequence_; abort_sequence_ = sequence;
    }
    auto rollback = [&] {
      if (!slot) {
        std::lock_guard guard(ccid_mutex_);
        if (abort_sequence_ == sequence) abort_sequence_ = previous;
      }
    };
    try {
      auto response = auxiliary.exchange(request);
      if (response != Bytes{0x90,0}) rollback();
      return response;
    } catch (...) { rollback(); throw; }
  }
  static std::uint8_t response_type(std::uint8_t command) {
    if (command == 0x62 || command == 0x6f || command == 0x69) return 0x80;
    if (command == 0x61 || command == 0x6c || command == 0x6d) return 0x82;
    if (command == 0x6b) return 0x83;
    if (command == 0x73) return 0x84;
    return 0x81;
  }
  void submit_ccid(Bytes packet) {
    std::lock_guard guard(ccid_mutex_);
    const bool matching_abort = packet[0] == 0x72 && !packet[5] && abort_sequence_ == packet[6];
    const bool pending = ccid_active_ || !ccid_jobs_.empty();
    if ((abort_sequence_ && !matching_abort) || (pending && !matching_abort) || ccid_jobs_.size() >= 2) {
      const auto type = response_type(packet[0]);
      ccid_ready_.push_back(Bytes{type,0,0,0,0,packet[5],packet[6],
          static_cast<std::uint8_t>(0x40 | (packet[5] ? 2 : icc_status_)),
          static_cast<std::uint8_t>(packet[5] ? 5 : abort_sequence_ ? 0xff : 0xe0),
          static_cast<std::uint8_t>(type == 0x81 ? clock_status_ : type == 0x82 ? 1 : 0)});
      return;
    }
    ccid_jobs_.push_back({std::move(packet), ccid_generation_, true});
    ccid_condition_.notify_one();
  }
  void run_ccid() {
    for (;;) {
      Job job;
      {
        std::unique_lock guard(ccid_mutex_);
        ccid_condition_.wait(guard, [this] { return ccid_stopping_ || !ccid_jobs_.empty(); });
        if (ccid_stopping_) return;
        job = std::move(ccid_jobs_.front()); ccid_jobs_.pop_front();
        ccid_active_ = true; active_kind_ = job.packet[0]; active_sequence_ = job.packet[6];
        active_generation_ = job.generation;
        next_wtx_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
      }
      try {
        auto response = card.exchange(job.packet);
        if (response.size() < 10 || response.size() > swpk::usb::kCcidMessageLength || response[5] != job.packet[5] || response[6] != job.packet[6] ||
            response[0] != response_type(job.packet[0])) throw std::runtime_error("invalid CCID backend response");
        std::lock_guard guard(ccid_mutex_);
        if (job.generation == ccid_generation_) {
          if (!response[5]) icc_status_ = response[7] & 3;
          if (response[0] == 0x81 && !response[5]) clock_status_ = response[9];
          if (job.packet[0] == 0x62 && !(response[7] & 0xc0)) clock_status_ = 0;
          if (job.packet[0] == 0x72 && !(response[7] & 0xc0)) abort_sequence_.reset();
          if (job.visible) ccid_ready_.push_back(std::move(response));
        }
        ccid_active_ = false;
        ccid_condition_.notify_all();
      } catch (...) {
        std::lock_guard guard(ccid_mutex_);
        ccid_failed_ = true; ccid_active_ = false; ccid_condition_.notify_all(); return;
      }
    }
  }
  void suspend() {
    if (model->configured()) usb_suspended_ = true;
  }
  void resume() {
    if (!usb_suspended_) return;
    usb_suspended_ = false;
    if (!model->configured() || !model->endpoint_exists(swpk::usb::kCcidOut)) return;
    // CCID1.1 resume requires an inactive occupied slot and a fresh insertion
    // indication. Reset only card session state: already committed endpoint,
    // model and ready replies must retain their original generation/sequence.
    if (abort_rpc(0,255) != Bytes{0x90,0})
      throw std::runtime_error("CCID resume cancellation failed");
    {
      std::lock_guard guard(ccid_mutex_);
      ccid_jobs_.push_back({Bytes{0x72,0,0,0,0,0,255,0,0,0},ccid_generation_,false});
      ccid_jobs_.push_back({Bytes{0x63,0,0,0,0,0,0,0,0,0},ccid_generation_,false});
    }
    ccid_condition_.notify_one();
    {
      std::unique_lock guard(ccid_mutex_);
      if (!ccid_condition_.wait_for(guard,std::chrono::seconds(2),[this] {
            return ccid_failed_ || (!ccid_active_ && ccid_jobs_.empty());
          }) || ccid_failed_ || icc_status_ != 1 || clock_status_ != 3)
        throw std::runtime_error("CCID resume power-off failed");
    }
    model->queue_input(swpk::usb::kCcidInterrupt,{0x50,0x03});
    if (std::getenv("SKE_TRACE_USB"))
      std::cerr << "ccid_resume_inactive preserved_transfer_generation=" << ccid_generation_ << '\n';
  }
  void reset() {
    usb_suspended_ = false;

    // A USB reset invalidates reports queued for the former interrupt IN
    // endpoint. Reconnect the private CTAPHID stream so socket-buffered
    // reports cannot be forwarded into the newly configured USB generation.
    fido.reset();
    fido = std::make_unique<FidoWire>(fido_path_);

#ifdef __linux__
    // A plain USB bus reset can leave the management generation unchanged.
    // Stop the service-side software-touch subscription before reenabling USB,
    // or a report produced while disconnected could be typed on reconnect.
    std::array<std::uint8_t,9> pause_keyboard{};
    pause_keyboard[0] = 13;
    if (auxiliary.exchange(pause_keyboard) != Bytes{0x90,0,0,0})
      throw std::runtime_error("USB keyboard reset failed");
#endif

    (void)abort_rpc(0,255);
    {
      std::lock_guard guard(ccid_mutex_);
      ++ccid_generation_; ccid_jobs_.clear(); ccid_ready_.clear();
      ccid_jobs_.push_back({Bytes{0x72,0,0,0,0,0,255,0,0,0}, ccid_generation_, false});
      ccid_jobs_.push_back({Bytes{0x63,0,0,0,0,0,0,0,0,0}, ccid_generation_, false});
    }
    ccid_condition_.notify_one();
    model->reset(); keyboard.clear(); next_keyboard_poll_ = {};
    std::unique_lock guard(ccid_mutex_);
    if (!ccid_condition_.wait_for(guard, std::chrono::seconds(2), [this] {
          return ccid_failed_ || (!ccid_active_ && ccid_jobs_.empty());
        }) || ccid_failed_) throw std::runtime_error("CCID reset failed");
  }
  void forward() {
    for (auto& packet : model->take_fido_output()) fido->write(packet);
    {
      std::lock_guard guard(ccid_mutex_);
      if (ccid_failed_) throw std::runtime_error("CCID backend disconnected");
      while (!ccid_ready_.empty() && !model->input_queue_full(swpk::usb::kCcidIn)) {
        model->queue_input(swpk::usb::kCcidIn, std::move(ccid_ready_.front())); ccid_ready_.pop_front();
      }
      const auto now = std::chrono::steady_clock::now();
      if (ccid_active_ && active_kind_ == 0x6f && active_generation_ == ccid_generation_ &&
          !abort_sequence_ && now >= next_wtx_ && !model->input_queue_full(swpk::usb::kCcidIn)) {
        model->queue_input(swpk::usb::kCcidIn, Bytes{0x80,0,0,0,0,0,active_sequence_,
            static_cast<std::uint8_t>(0x80 | icc_status_),1,0});
        next_wtx_ = now + std::chrono::milliseconds(500);
      }
    }
    for (auto& packet : model->take_ccid_output()) submit_ccid(std::move(packet));
    // Leave complete reports in the socket when the host has stopped reading
    // interrupt IN. Reading a batch first can exceed the model's 256-report
    // queue and terminate the composite bridge under normal USB backpressure.
    for (int i = 0; i < 64 && !model->input_queue_full(swpk::usb::kFidoIn); ++i) {
      auto packet = fido->read_one();
      if (!packet) break;
      model->queue_input(swpk::usb::kFidoIn, std::move(*packet));
    }
#ifdef __linux__
    poll_keyboard_usb_events();
#endif
    const auto now = std::chrono::steady_clock::now();
    while (!keyboard.empty() && keyboard.front().second <= now && !model->input_queue_full(0x81)) {
      model->queue_input(0x81, std::move(keyboard.front().first)); keyboard.pop_front();
    }
    model->poll_keyboard_idle();
  }
  void hold(const std::string& duration) {
    std::size_t end{};
    const auto ms = std::stoul(duration, &end);
    if (end != duration.size() || ms > 60000 || keyboard.size() > 128)
      throw std::invalid_argument("invalid hold duration or keyboard queue full");
    std::array<std::uint8_t,9> packet{};
    packet[0] = 6; packet[1] = static_cast<std::uint8_t>(ms >> 8); packet[2] = static_cast<std::uint8_t>(ms);
    const auto data = auxiliary.exchange(packet);
    if (data.size() < 4 || data[0] != 0x90 || data[1]) throw std::runtime_error("button request denied");
    schedule_keyboard_events(data);
  }
  void schedule_keyboard_events(const Bytes& data) {
    const auto count = (std::size_t(data[2]) << 8) | data[3];
    if (data.size() != 4 + count * 10 || count > 256 || keyboard.size() + count > 256)
      throw std::runtime_error("invalid keyboard event response");
    auto deadline = std::chrono::steady_clock::now();
    if (!keyboard.empty()) deadline = std::max(deadline, keyboard.back().second);
    for (std::size_t i = 4; i < data.size(); i += 10) {
      keyboard.push_back({Bytes(data.begin() + static_cast<std::ptrdiff_t>(i),
                               data.begin() + static_cast<std::ptrdiff_t>(i + 8)), deadline});
      deadline += std::chrono::milliseconds((std::uint16_t(data[i+8]) << 8) | data[i+9]);
    }
  }
  void poll_keyboard_usb_events() {
    const auto now = std::chrono::steady_clock::now();
    if (now < next_keyboard_poll_) return;
    next_keyboard_poll_ = now + std::chrono::milliseconds(10);
    std::array<std::uint8_t,11> packet{};
    packet[0] = 12;
    for (std::size_t i = 0; i < 8; ++i)
      packet[8-i] = static_cast<std::uint8_t>(usb_state_.generation >> (i * 8));
    const auto capacity = std::size_t(256) - keyboard.size();
    packet[9] = static_cast<std::uint8_t>(capacity >> 8);
    packet[10] = static_cast<std::uint8_t>(capacity);
    const auto data = auxiliary.exchange(packet);
    if (data.size() < 4 || data[0] != 0x90 || data[1])
      throw std::runtime_error("invalid USB keyboard event response");
    if (model->configured() && model->endpoint_exists(0x81))
      schedule_keyboard_events(data);
    else if (data.size() != 4 + (((std::size_t(data[2]) << 8) | data[3]) * 10))
      throw std::runtime_error("invalid USB keyboard event count");
  }
};
void wire_test(Backend& backend) {
  std::string line;
  while (std::getline(std::cin, line)) {
    try {
      std::istringstream input(line);
      std::string command, first, second;
      input >> command >> first >> second;
      Bytes data;
      bool stalled = false, pending = false;
      if (command == "control") {
        auto result = backend.model->control(Setup::decode(unhex(first)), unhex(second));
        stalled = result.stalled; data = std::move(result.data);
      } else if (command == "out") {
        const auto endpoint = unhex(first);
        if (endpoint.size() != 1) throw std::invalid_argument("endpoint must be one byte");
        stalled = !backend.model->output(endpoint[0], unhex(second));
      } else if (command == "in") {
        const auto endpoint = unhex(first);
        if (endpoint.size() != 1) throw std::invalid_argument("endpoint must be one byte");
        backend.forward();
        const auto capacity = std::stoul(second);
        if (capacity > 32786) throw std::invalid_argument("capacity too large");
        if (!backend.model->configured() || !backend.model->endpoint_exists(endpoint[0]) ||
            backend.model->endpoint_halted(endpoint[0]) || !(endpoint[0] & 0x80)) stalled = true;
        else {
          auto result = backend.model->input(endpoint[0], capacity);
          if (result) data = std::move(*result); else pending = true;
        }
      } else if (command == "reset") {
        backend.reset();
      } else if (command == "suspend") {
        backend.suspend();
      } else if (command == "resume") {
        backend.resume();
      } else if (command == "hold") {
        backend.hold(first);
      } else if (command == "reenumerate") {
        backend.next_usb_poll_ = {};
        if (backend.poll_reboot()) backend.apply_reboot();
      } else throw std::invalid_argument("unknown wire-test operation");
      backend.forward();
      std::cout << "{\"stalled\":" << (stalled ? "true" : "false")
                << ",\"pending\":" << (pending ? "true" : "false")
                << ",\"data\":\"" << hex(data) << "\"}" << std::endl;
    } catch (const std::exception&) {
      std::cout << "{\"error\":\"invalid request or backend failure\"}" << std::endl;
    } catch (const swpk::pcsc::WireError&) {
      throw std::runtime_error("card backend disconnected");
    }
  }
}
}  // namespace swpk::usb::native

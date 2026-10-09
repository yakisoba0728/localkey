#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/daemon/loop.hpp"
#include "fake_transport.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <thread>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace swpk;
using namespace swpk::test;
using namespace std::chrono_literals;

namespace {

// Handler whose "makeCredential" blocks in a fake UP wait until cancelled or
// released, publishing UPNEEDED while blocked. getInfo answers instantly.
class SlowHandler final : public ctap::RequestHandler {
public:
  std::atomic<bool> release{false};
  std::atomic<bool> signing{false};
  std::atomic<int> calls{0};

  Result<std::vector<std::uint8_t>> handle_cbor(std::span<const std::uint8_t> req,
                                                ctap::CancelToken& cancel) override {
    ++calls;
    if (req.empty()) return std::unexpected(Status::InvalidLength);
    if (req[0] == 0x04) return std::vector<std::uint8_t>{0xA0};
    if (req[0] == 0x01) {
      cancel.set_up_needed(true);
      while (!release.load()) {
        if (cancel.is_cancelled()) {
          cancel.set_up_needed(false);
          return std::unexpected(Status::KeepaliveCancel);
        }
        std::this_thread::sleep_for(2ms);
      }
      cancel.set_up_needed(false);
      signing = true;
      std::this_thread::sleep_for(250ms);  // "TPM sign" while PROCESSING
      return std::vector<std::uint8_t>{0xA0};
    }
    return std::unexpected(Status::InvalidCommand);
  }
  std::vector<std::uint8_t> handle_u2f(std::span<const std::uint8_t>, ctap::CancelToken&) override {
    return {0x6D, 0x00};
  }
  bool supports_u2f() const override { return false; }
};

struct Rig {
  FakeTransport t;
  SlowHandler h;
  crypto::Provider rng;
  daemon::Loop loop{t, h, rng};
  std::thread hid;
  Rig() { hid = std::thread([&] { loop.run(); }); }
  ~Rig() {
    loop.stop();
    hid.join();
  }
  std::uint32_t init() {
    const std::uint8_t nonce[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    t.host_write(make_frames(ctap::kBroadcastCid, ctap::kCmdInit, nonce).front());
    auto r = t.host_read(2s);
    REQUIRE(r.has_value());
    REQUIRE(cmd_of(*r) == ctap::kCmdInit);
    return static_cast<std::uint32_t>((*r)[15]) | (static_cast<std::uint32_t>((*r)[16]) << 8) |
           (static_cast<std::uint32_t>((*r)[17]) << 16) | (static_cast<std::uint32_t>((*r)[18]) << 24);
  }
};

class SlowU2fHandler final : public ctap::RequestHandler {
public:
  std::atomic<bool> entered{false};
  std::atomic<bool> release{false};

  Result<std::vector<std::uint8_t>> handle_cbor(std::span<const std::uint8_t>,
                                                ctap::CancelToken&) override {
    return std::unexpected(Status::InvalidCommand);
  }
  std::vector<std::uint8_t> handle_u2f(std::span<const std::uint8_t>,
                                       ctap::CancelToken& cancel) override {
    entered = true;
    while (!release.load()) std::this_thread::sleep_for(2ms);
    return cancel.is_cancelled() ? std::vector<std::uint8_t>{0x69, 0x85}
                                 : std::vector<std::uint8_t>{0x90, 0x00};
  }
  bool supports_u2f() const override { return true; }
};

struct U2fRig {
  FakeTransport t;
  SlowU2fHandler h;
  crypto::Provider rng;
  daemon::Loop loop{t, h, rng};
  std::thread hid;
  U2fRig() { hid = std::thread([&] { loop.run(); }); }
  ~U2fRig() { h.release = true; loop.stop(); hid.join(); }
  std::uint32_t init() {
    const std::uint8_t nonce[8] = {1, 3, 5, 7, 9, 2, 4, 6};
    t.host_write(make_frames(ctap::kBroadcastCid, ctap::kCmdInit, nonce).front());
    auto answer = t.host_read(2s);
    REQUIRE(answer.has_value());
    REQUIRE(cmd_of(*answer) == ctap::kCmdInit);
    return static_cast<std::uint32_t>((*answer)[15]) |
           (static_cast<std::uint32_t>((*answer)[16]) << 8) |
           (static_cast<std::uint32_t>((*answer)[17]) << 16) |
           (static_cast<std::uint32_t>((*answer)[18]) << 24);
  }
};

}  // namespace

TEST_CASE("getInfo produces a response and zero keepalives", "[loop]") {
  Rig r;
  auto cid = r.init();
  const std::uint8_t gi[] = {0x04};
  r.t.host_write(make_frames(cid, ctap::kCmdCbor, gi).front());
  auto resp = r.t.host_read(2s);
  REQUIRE(resp.has_value());
  REQUIRE(cid_of(*resp) == cid);
  REQUIRE(cmd_of(*resp) == ctap::kCmdCbor);
  REQUIRE(bcnt_of(*resp) == 2);
  REQUIRE((*resp)[7] == 0x00);
  REQUIRE((*resp)[8] == 0xA0);
  std::this_thread::sleep_for(150ms);
  REQUIRE(r.t.host_drain().empty());
  REQUIRE(r.loop.stats().keepalives == 0);
  REQUIRE(r.loop.stats().cbor_ok == 1);
}

TEST_CASE("UPNEEDED keepalives while blocked, PROCESSING after, then response", "[loop]") {
  Rig r;
  auto cid = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(cid, ctap::kCmdCbor, mc).front());
  int upneeded = 0;
  for (int i = 0; i < 3; ++i) {
    auto k = r.t.host_read(1s);
    REQUIRE(k.has_value());
    REQUIRE(cmd_of(*k) == ctap::kCmdKeepalive);
    REQUIRE(cid_of(*k) == cid);
    if ((*k)[7] == ctap::kKeepaliveUpNeeded) ++upneeded;
  }
  REQUIRE(upneeded == 3);
  r.h.release = true;
  int processing = 0;
  std::optional<hid::Report> resp;
  for (int i = 0; i < 20; ++i) {
    auto k = r.t.host_read(1s);
    REQUIRE(k.has_value());
    if (cmd_of(*k) == ctap::kCmdKeepalive) {
      if ((*k)[7] == ctap::kKeepaliveProcessing) ++processing;
      continue;
    }
    resp = *k;
    break;
  }
  REQUIRE(resp.has_value());
  REQUIRE(cmd_of(*resp) == ctap::kCmdCbor);
  REQUIRE((*resp)[7] == 0x00);
  REQUIRE(processing >= 1);
  // Nothing after the response.
  REQUIRE_FALSE(r.t.host_read(150ms).has_value());
}

TEST_CASE("CANCEL during UP yields KEEPALIVE_CANCEL on the same CID", "[loop]") {
  Rig r;
  auto cid = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(cid, ctap::kCmdCbor, mc).front());
  auto k = r.t.host_read(1s);
  REQUIRE(k.has_value());
  REQUIRE(cmd_of(*k) == ctap::kCmdKeepalive);
  r.t.host_write(make_frames(cid, ctap::kCmdCancel, {}).front());
  std::optional<hid::Report> resp;
  for (int i = 0; i < 20; ++i) {
    auto p = r.t.host_read(1s);
    REQUIRE(p.has_value());
    if (cmd_of(*p) == ctap::kCmdKeepalive) continue;
    resp = *p;
    break;
  }
  REQUIRE(resp.has_value());
  REQUIRE(cmd_of(*resp) == ctap::kCmdCbor);
  REQUIRE(bcnt_of(*resp) == 1);
  REQUIRE((*resp)[7] == static_cast<std::uint8_t>(Status::KeepaliveCancel));
  REQUIRE(r.loop.stats().cancels == 1);
}

TEST_CASE("CANCEL during U2F MSG is ignored and the response succeeds", "[loop][u2f-cancel]") {
  U2fRig r;
  const auto cid = r.init();
  const std::uint8_t apdu[] = {0x00, 0x03, 0x00, 0x00};
  r.t.host_write(make_frames(cid, ctap::kCmdMsg, apdu).front());
  for (int i = 0; i < 200 && !r.h.entered.load(); ++i) std::this_thread::sleep_for(2ms);
  REQUIRE(r.h.entered.load());
  r.t.host_write(make_frames(cid, ctap::kCmdCancel, {}).front());
  std::this_thread::sleep_for(50ms);  // let the HID loop ingest CANCEL first
  r.h.release = true;
  std::optional<hid::Report> answer;
  for (int i = 0; i < 20; ++i) {
    auto packet = r.t.host_read(1s);
    REQUIRE(packet.has_value());
    if (cmd_of(*packet) == ctap::kCmdKeepalive) continue;
    answer = *packet;
    break;
  }
  REQUIRE(answer.has_value());
  REQUIRE(cmd_of(*answer) == ctap::kCmdMsg);
  REQUIRE(bcnt_of(*answer) == 2);
  REQUIRE((*answer)[7] == 0x90);
  REQUIRE((*answer)[8] == 0x00);
  REQUIRE(r.loop.stats().cancels == 0);
}

TEST_CASE("same-CID INIT still aborts an in-flight U2F MSG", "[loop][u2f-cancel]") {
  U2fRig r;
  const auto cid = r.init();
  const std::uint8_t apdu[] = {0x00, 0x03, 0x00, 0x00};
  r.t.host_write(make_frames(cid, ctap::kCmdMsg, apdu).front());
  for (int i = 0; i < 200 && !r.h.entered.load(); ++i) std::this_thread::sleep_for(2ms);
  REQUIRE(r.h.entered.load());
  const std::uint8_t nonce[8] = {6, 4, 2, 9, 7, 5, 3, 1};
  r.t.host_write(make_frames(cid, ctap::kCmdInit, nonce).front());
  std::optional<hid::Report> init;
  for (int i = 0; i < 20; ++i) {
    auto packet = r.t.host_read(1s);
    REQUIRE(packet.has_value());
    if (cmd_of(*packet) == ctap::kCmdKeepalive) continue;
    init = *packet;
    break;
  }
  REQUIRE(init.has_value());
  REQUIRE(cmd_of(*init) == ctap::kCmdInit);
  REQUIRE(std::equal(nonce, nonce + 8, init->begin() + 7));
  REQUIRE(r.loop.stats().cancels == 1);
  r.h.release = true;
  REQUIRE_FALSE(r.t.host_read(150ms).has_value());
}

TEST_CASE("second channel gets CHANNEL_BUSY while first is in flight", "[loop]") {
  Rig r;
  auto c1 = r.init();
  auto c2 = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(c1, ctap::kCmdCbor, mc).front());
  REQUIRE(r.t.host_read(1s).has_value());  // a keepalive: worker is busy
  const std::uint8_t gi[] = {0x04};
  r.t.host_write(make_frames(c2, ctap::kCmdCbor, gi).front());
  std::optional<hid::Report> err;
  for (int i = 0; i < 20; ++i) {
    auto p = r.t.host_read(1s);
    REQUIRE(p.has_value());
    if (cid_of(*p) == c2) {
      err = *p;
      break;
    }
  }
  REQUIRE(err.has_value());
  REQUIRE(cmd_of(*err) == ctap::kCmdError);
  REQUIRE((*err)[7] == static_cast<std::uint8_t>(ctap::HidErr::ChannelBusy));
  r.h.release = true;
}

TEST_CASE("another CID gets CHANNEL_BUSY for PING while the worker is busy", "[loop][arbitration]") {
  Rig r;
  auto c1 = r.init();
  auto c2 = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(c1, ctap::kCmdCbor, mc).front());
  REQUIRE(r.t.host_read(1s).has_value());
  const std::uint8_t ping[] = {1, 2, 3};
  r.t.host_write(make_frames(c2, ctap::kCmdPing, ping).front());
  std::optional<hid::Report> busy;
  for (int i = 0; i < 20; ++i) {
    auto p = r.t.host_read(1s);
    REQUIRE(p.has_value());
    if (cid_of(*p) == c2) {
      busy = *p;
      break;
    }
  }
  REQUIRE(busy.has_value());
  REQUIRE(cmd_of(*busy) == ctap::kCmdError);
  REQUIRE((*busy)[7] == static_cast<std::uint8_t>(ctap::HidErr::ChannelBusy));
  r.h.release = true;
}

TEST_CASE("same CID cannot interleave PING with a processing CBOR request", "[loop][same-cid-atomicity]") {
  Rig r;
  const auto cid = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(cid, ctap::kCmdCbor, mc).front());
  auto keepalive = r.t.host_read(1s);
  REQUIRE(keepalive.has_value());
  REQUIRE(cmd_of(*keepalive) == ctap::kCmdKeepalive);
  const std::uint8_t ping[] = {1, 2, 3};
  r.t.host_write(make_frames(cid, ctap::kCmdPing, ping).front());
  std::optional<hid::Report> busy;
  for (int i = 0; i < 20; ++i) {
    auto packet = r.t.host_read(1s);
    REQUIRE(packet.has_value());
    if (cmd_of(*packet) == ctap::kCmdKeepalive) continue;
    busy = *packet;
    break;
  }
  REQUIRE(busy.has_value());
  REQUIRE(cmd_of(*busy) == ctap::kCmdError);
  REQUIRE((*busy)[7] == static_cast<std::uint8_t>(ctap::HidErr::ChannelBusy));
  r.h.release = true;
  std::optional<hid::Report> original;
  for (int i = 0; i < 20; ++i) {
    auto packet = r.t.host_read(1s);
    REQUIRE(packet.has_value());
    if (cmd_of(*packet) == ctap::kCmdKeepalive) continue;
    original = *packet;
    break;
  }
  REQUIRE(original.has_value());
  REQUIRE(cmd_of(*original) == ctap::kCmdCbor);
  REQUIRE((*original)[7] == 0x00);
}

TEST_CASE("reconnect discards a late worker response before the next INIT", "[loop][reconnect]") {
  Rig r;
  auto old_cid = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(old_cid, ctap::kCmdCbor, mc).front());
  auto keepalive = r.t.host_read(1s);
  REQUIRE(keepalive.has_value());
  REQUIRE(cmd_of(*keepalive) == ctap::kCmdKeepalive);
  r.h.release = true;
  for (int i = 0; i < 100 && !r.h.signing.load(); ++i) {
    std::this_thread::sleep_for(2ms);
  }
  REQUIRE(r.h.signing.load());
  r.t.host_reconnect();
  REQUIRE_FALSE(r.t.host_read(500ms).has_value());
  auto new_cid = r.init();
  REQUIRE(new_cid != old_cid);
  const std::uint8_t gi[] = {0x04};
  r.t.host_write(make_frames(new_cid, ctap::kCmdCbor, gi).front());
  auto response = r.t.host_read(2s);
  REQUIRE(response.has_value());
  REQUIRE(cid_of(*response) == new_cid);
  REQUIRE(cmd_of(*response) == ctap::kCmdCbor);
  REQUIRE((*response)[7] == 0x00);
  REQUIRE_FALSE(r.t.host_read(150ms).has_value());
}

TEST_CASE("allocated INIT discards a late response from its aborted transaction", "[loop][resync]") {
  Rig r;
  const auto cid = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(cid, ctap::kCmdCbor, mc).front());
  auto keepalive = r.t.host_read(1s);
  REQUIRE(keepalive.has_value());
  REQUIRE(cmd_of(*keepalive) == ctap::kCmdKeepalive);
  r.h.release = true;
  for (int i = 0; i < 100 && !r.h.signing.load(); ++i) {
    std::this_thread::sleep_for(2ms);
  }
  REQUIRE(r.h.signing.load());

  const std::uint8_t nonce[8] = {1, 3, 5, 7, 2, 4, 6, 8};
  r.t.host_write(make_frames(cid, ctap::kCmdInit, nonce).front());
  std::optional<hid::Report> init;
  for (int i = 0; i < 10; ++i) {
    auto next = r.t.host_read(1s);
    REQUIRE(next.has_value());
    if (cmd_of(*next) == ctap::kCmdInit) { init = *next; break; }
    REQUIRE(cmd_of(*next) == ctap::kCmdKeepalive);
  }
  REQUIRE(init.has_value());
  REQUIRE(cid_of(*init) == cid);
  REQUIRE_FALSE(r.t.host_read(500ms).has_value());

  const std::uint8_t ping[] = {9, 8, 7};
  r.t.host_write(make_frames(cid, ctap::kCmdPing, ping).front());
  auto pong = r.t.host_read(2s);
  REQUIRE(pong.has_value());
  REQUIRE(cmd_of(*pong) == ctap::kCmdPing);
  REQUIRE(cid_of(*pong) == cid);
}


TEST_CASE("allocated INIT flushes a late worker reply over a private Unix socket", "[loop][resync][socket]") {
  class SocketRig {
  public:
    std::string path = "/tmp/swpk-resync-" + std::to_string(::getpid()) + "-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sock";
    std::unique_ptr<hid::Transport> transport = hid::make_socket_transport(path);
    SlowHandler handler;
    crypto::Provider rng;
    daemon::Loop loop{*transport, handler, rng};
    std::thread worker;
    int client{-1};

    SocketRig() {
      if (!transport->open()) throw std::runtime_error("private socket transport open failed");
      worker = std::thread([this] { loop.run(); });
      client = ::socket(AF_UNIX, SOCK_STREAM, 0);
      if (client < 0) throw std::runtime_error("private socket client creation failed");
      sockaddr_un address{};
      address.sun_family = AF_UNIX;
      std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
      if (::connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)))
        throw std::runtime_error("private socket client connect failed");
    }
    ~SocketRig() {
      if (client >= 0) ::close(client);
      loop.stop();
      if (worker.joinable()) worker.join();
      transport->close();
    }
    void send_report(const hid::Report& report) {
      std::size_t sent = 0;
      while (sent < report.size()) {
        const auto count = ::send(client, report.data() + sent, report.size() - sent, 0);
        if (count <= 0) throw std::runtime_error("private socket report send failed");
        sent += static_cast<std::size_t>(count);
      }
    }
    std::optional<hid::Report> read_report(int timeout_ms) {
      pollfd wait{client, POLLIN, 0};
      const auto ready = ::poll(&wait, 1, timeout_ms);
      if (ready <= 0) return std::nullopt;
      hid::Report report{};
      std::size_t got = 0;
      while (got < report.size()) {
        const auto count = ::recv(client, report.data() + got, report.size() - got, 0);
        if (count <= 0) throw std::runtime_error("private socket report receive failed");
        got += static_cast<std::size_t>(count);
      }
      return report;
    }
    std::uint32_t init() {
      const std::uint8_t nonce[8] = {2, 4, 6, 8, 1, 3, 5, 7};
      send_report(make_frames(ctap::kBroadcastCid, ctap::kCmdInit, nonce).front());
      auto response = read_report(2000);
      if (!response || cmd_of(*response) != ctap::kCmdInit)
        throw std::runtime_error("private socket INIT response missing");
      return static_cast<std::uint32_t>((*response)[15]) |
             (static_cast<std::uint32_t>((*response)[16]) << 8) |
             (static_cast<std::uint32_t>((*response)[17]) << 16) |
             (static_cast<std::uint32_t>((*response)[18]) << 24);
    }
  } rig;
  const auto cid = rig.init();
  const std::uint8_t make_credential[] = {0x01};
  rig.send_report(make_frames(cid, ctap::kCmdCbor, make_credential).front());
  auto keepalive = rig.read_report(1000);
  REQUIRE(keepalive.has_value());
  REQUIRE(cmd_of(*keepalive) == ctap::kCmdKeepalive);
  rig.handler.release = true;
  for (int i = 0; i < 100 && !rig.handler.signing.load(); ++i)
    std::this_thread::sleep_for(2ms);
  REQUIRE(rig.handler.signing.load());

  const std::uint8_t nonce[8] = {1, 3, 5, 7, 2, 4, 6, 8};
  rig.send_report(make_frames(cid, ctap::kCmdInit, nonce).front());
  std::optional<hid::Report> init;
  for (int i = 0; i < 10; ++i) {
    auto next = rig.read_report(1000);
    REQUIRE(next.has_value());
    if (cmd_of(*next) == ctap::kCmdInit) { init = *next; break; }
    REQUIRE(cmd_of(*next) == ctap::kCmdKeepalive);
  }
  REQUIRE(init.has_value());
  REQUIRE(cid_of(*init) == cid);
  REQUIRE_FALSE(rig.read_report(500).has_value());
  const std::uint8_t ping[] = {9, 8, 7};
  rig.send_report(make_frames(cid, ctap::kCmdPing, ping).front());
  auto pong = rig.read_report(2000);
  REQUIRE(pong.has_value());
  REQUIRE(cmd_of(*pong) == ctap::kCmdPing);
  REQUIRE(cid_of(*pong) == cid);
}

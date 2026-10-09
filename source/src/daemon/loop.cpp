#include "swpasskey/daemon/loop.hpp"

#include "swpasskey/log/log.hpp"
#include "swpasskey/hid/card_wire.hpp"

#include <chrono>
#include <cstdio>
#include <string>

namespace swpk::daemon {
namespace {

using Clock = std::chrono::steady_clock;

// Read timeouts: tight while a transaction is in flight (keepalive + response
// latency), relaxed while assembling (500 ms inter-packet timer), long when idle.
constexpr auto kBusyPoll = std::chrono::milliseconds(5);
constexpr auto kAssemblingPoll = std::chrono::milliseconds(50);
constexpr auto kIdlePoll = std::chrono::milliseconds(250);

std::string hex32(std::uint32_t v) {
  char buf[12];
  std::snprintf(buf, sizeof(buf), "%08x", v);
  return buf;
}

}  // namespace

Loop::Loop(hid::Transport& transport, ctap::RequestHandler& handler, crypto::Provider& rng,
           std::string card_socket)
    : transport_(transport),
      handler_(handler),
      device_(rng, static_cast<std::uint8_t>(handler.supports_u2f()
                                                 ? (ctap::kCapCbor | ctap::kCapWink)
                                                 : (ctap::kCapCbor | ctap::kCapNmsg)),
              handler.supports_u2f(), !card_socket.empty()),
      card_socket_(std::move(card_socket)) {
  (void)synchronize_reboot();
}

bool Loop::synchronize_reboot() {
  if (card_socket_.empty()) return true;
  const auto response = hid::card_command(card_socket_, 0xfe);
  if (!response || response->size() != 11 || (*response)[0] != 1) return true;
  std::uint64_t generation = 0;
  for (std::size_t i = 1; i < 9; ++i) generation = (generation << 8) | (*response)[i];
  if (!reboot_generation_) { reboot_generation_ = generation; return true; }
  if (generation == *reboot_generation_) return true;
  {
    std::lock_guard guard(mu_);
    if (inflight_.cmd) { inflight_.token.cancel(); return false; }
    device_.reboot();
  }
  if (!handler_.reboot()) { stop(); return false; }
  reboot_generation_ = generation;
  log::debug("management_reboot_volatile_state_cleared");
  return true;
}

bool Loop::synchronize_transport_session() {
  const auto generation = transport_.connection_generation();
  if (generation == transport_generation_) return false;
  transport_generation_ = generation;
  std::lock_guard guard(mu_);
  ++transport_epoch_;
  if (inflight_.cmd) inflight_.token.cancel();
  outbox_.clear();
  device_.reboot();
  return true;
}

Loop::~Loop() {
  stop();
  if (worker_.joinable()) {
    worker_.join();
  }
}

void Loop::stop() {
  stop_.store(true);
  std::lock_guard<std::mutex> lk(mu_);
  inflight_.token.cancel();
  worker_cv_.notify_all();
}

Loop::Stats Loop::stats() const {
  std::lock_guard<std::mutex> lk(mu_);
  return stats_;
}

bool Loop::write_all(std::vector<hid::Report> reports) {
  for (const auto& r : reports) {
    if (!transport_.write(r)) {
      log::error("hid_write_failed");
      return false;
    }
  }
  return true;
}

void Loop::worker_main() {
  for (;;) {
    ctap::Message msg;
    std::uint64_t work_epoch;
    {
      std::unique_lock<std::mutex> lk(mu_);
      worker_cv_.wait(lk, [&] { return stop_.load() || inflight_.cmd.has_value(); });
      if (stop_.load()) {
        return;
      }
      msg = *inflight_.cmd;  // keep the slot occupied while we work
      work_epoch = inflight_epoch_;
    }

    const auto t0 = Clock::now();
    ctap::Message resp;
    resp.cid = msg.cid;
    resp.cmd = msg.cmd;
    bool ok = true;
    Status profile_status = Status::Ok;
    if (!card_socket_.empty() && (msg.cmd == ctap::kCmdCbor || msg.cmd == ctap::kCmdMsg)) {
      auto enabled = hid::card_command(card_socket_, 0);
      if (!enabled || enabled->size() != 2) profile_status = Status::Other;
      else {
        const auto bits = (std::uint16_t((*enabled)[0]) << 8) | (*enabled)[1];
        if (!(bits & (msg.cmd == ctap::kCmdCbor ? 0x200 : 2)))
          profile_status = Status::NotAllowed;
      }
    }
    if (msg.cmd == 0x42 || msg.cmd == 0x43) {
      auto result = hid::card_command(card_socket_, msg.cmd, msg.payload);
      if (result) resp.payload = std::move(*result);
      else {
        resp.cmd = ctap::kCmdError;
        resp.payload = {static_cast<std::uint8_t>(ctap::HidErr::Other)};
        ok = false;
      }
    } else if (profile_status != Status::Ok) {
      ok = false;
      resp.payload = msg.cmd == ctap::kCmdCbor
          ? std::vector<std::uint8_t>{static_cast<std::uint8_t>(profile_status)}
          : std::vector<std::uint8_t>{0x69, 0x85};
    } else if (msg.cmd == ctap::kCmdCbor) {
      auto r = handler_.handle_cbor_channel(msg.payload, inflight_.token, msg.cid);
      if (r) {
        resp.payload.reserve(r->size() + 1);
        resp.payload.push_back(0x00);
        resp.payload.insert(resp.payload.end(), r->begin(), r->end());
      } else {
        ok = false;
        resp.payload.push_back(static_cast<std::uint8_t>(r.error()));
      }
      const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0);
      log::debug("cbor_done", {{"cid", hex32(msg.cid)},
                               {"status", std::to_string(resp.payload[0])},
                               {"ms", std::to_string(ms.count())}});
    } else {
      resp.payload = handler_.handle_u2f(msg.payload, inflight_.token);
    }

    {
      // Publish the response and release the slot atomically so the HID thread
      // never writes a keepalive after the response INIT packet.
      std::lock_guard<std::mutex> lk(mu_);
      if (work_epoch != transport_epoch_) {
        // The old client disconnected while this operation was in flight.
        // Keep its cancellation token until the worker has actually stopped,
        // then discard its reply before admitting the next client's reports.
        inflight_.cmd.reset();
        inflight_.token.reset();
        continue;
      }
      auto frames = device_.frame(resp);
      outbox_.insert(outbox_.end(), frames.begin(), frames.end());
      inflight_.cmd.reset();
      inflight_.token.reset();
      if (ok) {
        ++stats_.cbor_ok;
      } else {
        ++stats_.cbor_err;
      }
    }
  }
}

bool Loop::run() {
  worker_ = std::thread([this] { worker_main(); });

  bool healthy = true;
  while (!stop_.load()) {
    if (synchronize_transport_session()) continue;
    // 1. Drain outbox and decide whether a keepalive is due.
    std::vector<hid::Report> to_write;
    std::optional<std::uint32_t> busy_cid;
    bool draining_old_session = false;
    {
      std::lock_guard<std::mutex> lk(mu_);
      to_write.swap(outbox_);
      draining_old_session = inflight_.cmd && inflight_epoch_ != transport_epoch_;
      if (inflight_.cmd && !draining_old_session) {
        busy_cid = inflight_.cid;
        const auto now = Clock::now();
        if (now - inflight_.last_keepalive >= ctap::kKeepaliveInterval) {
          inflight_.last_keepalive = now;
          to_write.push_back(ctap::HidDevice::keepalive_packet(
              inflight_.cid, inflight_.token.keepalive_status()));
          ++stats_.keepalives;
        }
      }
    }
    if (!write_all(std::move(to_write))) {
      healthy = false;
      break;
    }
    if (synchronize_transport_session()) continue;

    // The prior session's worker still owns its cancellation token. Wait for
    // that worker to finish before reading commands from the new socket.
    if (draining_old_session) {
      std::this_thread::sleep_for(kBusyPoll);
      continue;
    }

    if (!synchronize_reboot()) {
      std::this_thread::sleep_for(kBusyPoll);
      continue;
    }

    // 2. Inter-packet timeout on a partial assembly.
    if (auto t = device_.poll_timeout()) {
      if (!write_all({*t})) {
        healthy = false;
        break;
      }
    }

    // 3. Read with a bounded wait.
    const auto timeout = busy_cid                ? kBusyPoll
                         : device_.assembling()  ? kAssemblingPoll
                         : !card_socket_.empty() ? kAssemblingPoll : kIdlePoll;
    auto rd = transport_.read(timeout);
    if (!rd) {
      log::error("hid_read_failed");
      healthy = false;
      break;
    }
    if (synchronize_transport_session()) continue;
    if (!rd->has_value()) {
      continue;
    }
    // A management commit can happen while read() is waiting. Synchronize
    // before allocating a fresh CID or accepting another authenticator command.
    if (!synchronize_reboot()) continue;

    // 4. Ingest under the lock so the busy/idle decision cannot race with a
    //    worker completion. ingest() never blocks or does I/O.
    std::vector<hid::Report> replies;
    {
      std::lock_guard<std::mutex> lk(mu_);
      const std::optional<std::uint32_t> now_busy =
          inflight_.cmd ? std::optional<std::uint32_t>{inflight_.cid} : std::nullopt;
      auto ing = device_.ingest(**rd, now_busy);
      replies = std::move(ing.reply);
      if (ing.resync_cid) {
        // CTAPHID_INIT on an allocated CID aborts that channel's transaction.
        // A worker may already have completed, so flush its queued reports;
        // if it is still running, invalidate its epoch before releasing mu_.
        const auto cid = *ing.resync_cid;
        std::erase_if(outbox_, [cid](const hid::Report& report) {
          const auto report_cid = static_cast<std::uint32_t>(report[0]) |
                                  (static_cast<std::uint32_t>(report[1]) << 8) |
                                  (static_cast<std::uint32_t>(report[2]) << 16) |
                                  (static_cast<std::uint32_t>(report[3]) << 24);
          return report_cid == cid;
        });
        if (inflight_.cmd && inflight_.cid == cid) ++transport_epoch_;
      }
      // CTAPHID_CANCEL applies only to a running CBOR request. INIT resync
      // still aborts any command on its own CID, including CTAP1/U2F MSG.
      if (ing.cancel_inflight && inflight_.cmd &&
          (ing.resync_cid || inflight_.cmd->cmd == ctap::kCmdCbor)) {
        inflight_.token.cancel();
        ++stats_.cancels;
      }
      if (ing.to_worker) {
        inflight_.cid = ing.to_worker->cid;
        inflight_.token.reset();
        inflight_epoch_ = transport_epoch_;
        inflight_.started = Clock::now();
        inflight_.last_keepalive = inflight_.started;
        inflight_.cmd = std::move(ing.to_worker);
        worker_cv_.notify_one();
      }
    }
    if (!write_all(std::move(replies))) {
      healthy = false;
      break;
    }
  }

  stop();
  if (worker_.joinable()) {
    worker_.join();
  }
  return healthy;
}

}  // namespace swpk::daemon

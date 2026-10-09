#pragma once

#include "swpasskey/hid/transport.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <utility>

namespace swpk::hid {

// The descriptor has no Report ID and declares exactly 64 output bytes. Some
// macOS callers include a leading zero Report ID in the callback buffer.
inline std::optional<Report> normalize_iokit_output(
    std::uint32_t report_id, std::span<const std::uint8_t> data) {
  if (report_id != 0) return std::nullopt;
  if (data.size() == kReportSize + 1 && data.front() == 0) data = data.subspan(1);
  if (data.size() != kReportSize) return std::nullopt;
  Report report{};
  std::copy(data.begin(), data.end(), report.begin());
  return report;
}

// The full CTAPHID request can occupy 129 reports. Admit at least one entire
// burst without depending on the daemon thread's scheduling. Once full, the
// IOKit callback returns an error to the host instead of discarding old input.
class IokitReportInbox {
public:
  static constexpr std::size_t kCapacity = 256;

  bool push(Report report) {
    if (reports_.size() >= kCapacity) return false;
    reports_.push_back(std::move(report));
    return true;
  }

  std::optional<Report> pop() {
    if (reports_.empty()) return std::nullopt;
    Report report = reports_.front();
    reports_.pop_front();
    return report;
  }

  bool empty() const { return reports_.empty(); }
  std::size_t size() const { return reports_.size(); }

private:
  std::deque<Report> reports_;
};

}  // namespace swpk::hid

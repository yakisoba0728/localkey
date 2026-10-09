// Native macOS OTP keyboard + eight-byte feature-report device.
// Requires a legitimately provisioned com.apple.developer.hid.virtual.device
// entitlement. The private socket talks to the same CCID/OTP protocol core.
#import <Foundation/Foundation.h>
#import <IOKit/hid/IOHIDKeys.h>
#import <IOKit/hidsystem/IOHIDUserDevice.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <charconv>
#include <cstring>
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
    int result{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || result < 0 || result > 60000)
        throw std::invalid_argument("hold duration must be an integer from 0 through 60000 milliseconds");
    return result;
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
    explicit Wire(const std::string& path) {
        struct stat st{};
        if (lstat(path.c_str(), &st) != 0 || !S_ISSOCK(st.st_mode) ||
            st.st_uid != geteuid() || (st.st_mode & 0077) != 0) {
            throw std::runtime_error("socket must be a private socket owned by this user");
        }
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (path.size() >= sizeof(addr.sun_path)) throw std::runtime_error("socket path too long");
        std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
        fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd_ < 0) throw std::runtime_error("socket creation failed");
        int one = 1;
        setsockopt(fd_, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        timeval timeout{30, 0};
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(fd_); fd_ = -1;
            throw std::runtime_error("cannot connect to card service");
        }
    }
    ~Wire() { if (fd_ >= 0) ::close(fd_); }
    std::vector<std::uint8_t> exchange(std::span<const std::uint8_t> packet) {
        std::lock_guard lock(mu_);
        const auto n = packet.size();
        const std::array<std::uint8_t, 4> prefix{
            static_cast<std::uint8_t>(n >> 24), static_cast<std::uint8_t>(n >> 16),
            static_cast<std::uint8_t>(n >> 8), static_cast<std::uint8_t>(n)};
        transfer(prefix.data(), prefix.size(), true);
        transfer(packet.data(), packet.size(), true);
        std::array<std::uint8_t, 4> size{};
        transfer(size.data(), size.size(), false);
        const auto count = (std::uint32_t(size[0]) << 24) | (std::uint32_t(size[1]) << 16) |
                           (std::uint32_t(size[2]) << 8) | size[3];
        if (count > 32786) throw std::runtime_error("oversized wire response");
        std::vector<std::uint8_t> data(count);
        transfer(data.data(), data.size(), false);
        return data;
    }
    std::array<std::uint8_t, 8> feature(bool send, std::span<const std::uint8_t> report = {}) {
        std::array<std::uint8_t, 9> packet{};
        packet[0] = send ? 1 : 2;
        if (send) {
            if (report.size() != 8) throw std::runtime_error("invalid OTP feature report");
            std::copy(report.begin(), report.end(), packet.begin() + 1);
        }
        const auto data = exchange(packet);
        if (data.size() != 8) throw std::runtime_error("invalid OTP feature response");
        std::array<std::uint8_t, 8> result{};
        std::copy(data.begin(), data.end(), result.begin());
        return result;
    }
private:
    void transfer(const void* buffer, std::size_t length, bool writing) {
        auto* data = const_cast<std::uint8_t*>(static_cast<const std::uint8_t*>(buffer));
        while (length) {
            const auto n = writing ? ::send(fd_, data, length, 0) : ::recv(fd_, data, length, 0);
            if (n <= 0) throw std::runtime_error("card service disconnected or timed out");
            data += n;
            length -= static_cast<std::size_t>(n);
        }
    }
    int fd_{-1};
    std::mutex mu_;
};
}

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--help") {
        std::cout << "ske-otpd --socket PATH\n"
                     "After entitled signing, forwards OTP HID and keyboard reports.\n"
                     "Enter 1 or 2 to request a slot press; the card service confirms user presence.\n"
                     "Enter hold N to model a hold/release of N milliseconds.\n"
                     "ske-otpd --wire-test PATH [--hold-ms N] exercises socket reports without creating an OS device.\n";
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
        std::array<std::uint8_t, 9> identity_request{};
        identity_request[0] = 4;
        const auto identity = wire.exchange(identity_request);
        if (identity.size() != 7) throw std::runtime_error("invalid card identity response");
        const auto serial = std::to_string((std::uint32_t(identity[3]) << 24) | (std::uint32_t(identity[4]) << 16) |
                                          (std::uint32_t(identity[5]) << 8) | identity[6]);
        if (wire_test) {
            const auto status = wire.feature(false);
            std::array<std::uint8_t, 9> press{};
            press[0] = 3; press[1] = 1;
            if (test_hold >= 0) press = hold_packet(test_hold);
            const auto response = wire.exchange(press);
            auto hex = [](std::span<const std::uint8_t> value) {
                constexpr char alphabet[] = "0123456789abcdef";
                std::string result;
                for (const auto byte : value) { result += alphabet[byte >> 4]; result += alphabet[byte & 15]; }
                return result;
            };
            std::cout << "{\"serial\":" << serial << ",\"status\":\"" << hex(status)
                      << "\",\"keyboard_events\":\"" << hex(response) << "\"}\n";
            return 0;
        }
        @autoreleasepool {
            NSDictionary* properties = @{
                @(kIOHIDReportDescriptorKey): [NSData dataWithBytes:descriptor length:sizeof(descriptor)],
                @(kIOHIDVendorIDKey): @0x1209,
                @(kIOHIDProductIDKey): @0xf055,
                @(kIOHIDVersionNumberKey): @0x0400,
                @(kIOHIDManufacturerKey): @"Local software emulator",
                @(kIOHIDProductKey): @"Software OTP keyboard development device",
                @(kIOHIDSerialNumberKey): [NSString stringWithUTF8String:serial.c_str()],
                @(kIOHIDTransportKey): @"USB",
                @(kIOHIDPrimaryUsagePageKey): @1,
                @(kIOHIDPrimaryUsageKey): @6,
                @(kIOHIDMaxInputReportSizeKey): @8,
                @(kIOHIDMaxOutputReportSizeKey): @1,
                @(kIOHIDMaxFeatureReportSizeKey): @8,
            };
            auto device = IOHIDUserDeviceCreateWithProperties(kCFAllocatorDefault, (__bridge CFDictionaryRef)properties, 0);
            if (!device) {
                std::cerr << "IOHIDUserDevice requires entitled developer signing and provisioning.\n";
                return 1;
            }
            auto* backend = &wire;
            IOHIDUserDeviceRegisterSetReportBlock(device, ^IOReturn(IOHIDReportType type, uint32_t reportID, const uint8_t* data, CFIndex length) {
                if (type == kIOHIDReportTypeOutput) return kIOReturnSuccess; // LED status
                if (type != kIOHIDReportTypeFeature || reportID || !data || length != 8) return kIOReturnBadArgument;
                try { (void)backend->feature(true, {data, 8}); return kIOReturnSuccess; }
                catch (...) { return kIOReturnError; }
            });
            IOHIDUserDeviceRegisterGetReportBlock(device, ^IOReturn(IOHIDReportType type, uint32_t reportID, uint8_t* data, CFIndex* length) {
                if (type != kIOHIDReportTypeFeature || reportID || !data || !length || *length < 8) return kIOReturnBadArgument;
                try { const auto report = backend->feature(false); std::memcpy(data, report.data(), 8); *length = 8; return kIOReturnSuccess; }
                catch (...) { return kIOReturnError; }
            });
            auto queue = dispatch_queue_create("local.ske.otp", DISPATCH_QUEUE_SERIAL);
            auto cancelled = dispatch_semaphore_create(0);
            IOHIDUserDeviceSetDispatchQueue(device, queue);
            IOHIDUserDeviceSetCancelHandler(device, ^{ dispatch_semaphore_signal(cancelled); });
            IOHIDUserDeviceActivate(device);
            std::cout << "OTP HID active. Enter 1 or 2, hold N (milliseconds), or quit.\n";
            int result = 0;
            try {
                std::string line;
                while (std::getline(std::cin, line)) {
                    if (line == "quit") break;
                    std::array<std::uint8_t, 9> packet{};
                    if (line == "1" || line == "2") {
                        packet[0] = 3; packet[1] = static_cast<std::uint8_t>(line[0] - '0');
                    } else if (line.starts_with("hold ")) {
                        try { packet = hold_packet(hold_duration(line.substr(5))); }
                        catch (const std::invalid_argument& e) { std::cerr << e.what() << '\n'; continue; }
                    } else continue;
                    const auto response = wire.exchange(packet);
                    if (response.size() < 4 || response[0] != 0x90 || response[1]) {
                        std::cerr << "Card rejected the button request.\n"; continue;
                    }
                    const auto count = (std::size_t(response[2]) << 8) | response[3];
                    if (response.size() != 4 + count * 10) throw std::runtime_error("invalid keyboard event frame");
                    for (std::size_t i = 4; i < response.size(); i += 10) {
                        if (IOHIDUserDeviceHandleReportWithTimeStamp(device, mach_absolute_time(), response.data() + i, 8) != kIOReturnSuccess)
                            throw std::runtime_error("keyboard report injection failed");
                        const auto delay = (unsigned(response[i+8]) << 8) | response[i+9];
                        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
                    }
                }
            } catch (const std::exception& e) { std::cerr << e.what() << '\n'; result = 1; }
            const std::array<std::uint8_t, 8> release{};
            (void)IOHIDUserDeviceHandleReportWithTimeStamp(device, mach_absolute_time(), release.data(), 8);
            IOHIDUserDeviceCancel(device);
            if (dispatch_semaphore_wait(cancelled, dispatch_time(DISPATCH_TIME_NOW, 35 * NSEC_PER_SEC)) != 0)
                _Exit(1); // Teardown all callback threads before the wire's lifetime ends.
            CFRelease(device);
            return result;
        }
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}

// Public IOUSBHost synthetic-device transport. Requires legitimately provisioned
// com.apple.developer.usb.host-controller-interface. --wire-test creates no OS device.
#import <Foundation/Foundation.h>
#import <IOUSBHost/IOUSBHost.h>
#import <IOUSBHost/IOUSBHostCIEndpointStateMachine.h>
#import <IOUSBHost/IOUSBHostCIDeviceStateMachine.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "swpasskey/pcsc/reader.hpp"
#include "swpasskey/usb/composite.hpp"
#include "swpasskey/usb/profile.hpp"

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>

using swpk::usb::Bytes;
using swpk::usb::Composite;
using swpk::usb::Setup;
#include "backend.hpp"
using swpk::usb::native::Backend;
using swpk::usb::native::wire_test;
namespace {
struct ControlFlow {
  Setup setup;
  Bytes output, input;
  std::size_t offset{};
  bool stalled{}, evaluated{};
};
}  // namespace

@interface SkeUSBHost : NSObject {
 @public
  std::shared_ptr<Backend> backend_;
  IOUSBHostControllerInterface* controller_;
  IOUSBHostCIDeviceStateMachine* device_;
  NSMutableDictionary<NSNumber*,IOUSBHostCIEndpointStateMachine*>* endpoints_;
  NSMutableSet<NSNumber*>* busy_;
  dispatch_queue_t queue_, worker_;
  dispatch_source_t timer_;
  ControlFlow control_;
  std::uint64_t epoch_, start_time_;
  std::array<std::uint64_t,256> endpoint_generation_;
  bool stopped_, polling_;
  bool rebooting_, reboot_prepared_;
  std::chrono::steady_clock::time_point reboot_deadline_;
}
- (BOOL)start;
- (void)command:(IOUSBHostCIMessage)command;
- (void)doorbell:(IOUSBHostCIDoorbell)doorbell;
- (void)pump:(IOUSBHostCIEndpointStateMachine*)endpoint;
- (void)stop;
- (void)beginReboot;
@end

@implementation SkeUSBHost
- (BOOL)start {
  endpoint_generation_.fill(0);
  endpoints_ = [NSMutableDictionary new]; busy_ = [NSMutableSet new];
  queue_ = dispatch_queue_create("local.ske.usb.controller", DISPATCH_QUEUE_SERIAL);
  worker_ = dispatch_queue_create("local.ske.usb.backend", DISPATCH_QUEUE_SERIAL);
  start_time_ = mach_absolute_time();
  IOUSBHostCIMessage capabilities[2]{};
  capabilities[0].control = static_cast<std::uint32_t>(IOUSBHostCIMessageTypeControllerCapabilities) | IOUSBHostCIMessageControlNoResponse |
      IOUSBHostCIMessageControlValid | (1U << IOUSBHostCICapabilitiesMessageControlPortCountPhase);
  capabilities[0].data0 = 2U << IOUSBHostCICapabilitiesMessageData0ConnectionLatencyPhase;
  capabilities[1].control = static_cast<std::uint32_t>(IOUSBHostCIMessageTypePortCapabilities) | IOUSBHostCIMessageControlNoResponse |
      IOUSBHostCIMessageControlValid | (1U << IOUSBHostCIPortCapabilitiesMessageControlPortNumberPhase);
  capabilities[1].data0 = 63U;
  NSData* data = [NSData dataWithBytes:capabilities length:sizeof(capabilities)];
  NSError* error = nil;
  controller_ = [[IOUSBHostControllerInterface alloc] initWithCapabilities:data queue:queue_
      interruptRateHz:1000 error:&error
      commandHandler:^(IOUSBHostControllerInterface*, IOUSBHostCIMessage cmd) { [self command:cmd]; }
      doorbellHandler:^(IOUSBHostControllerInterface*, IOUSBHostCIDoorbell* bells, uint32_t count) {
        for (uint32_t i = 0; i < count; ++i) [self doorbell:bells[i]];
      } interestHandler:nil];
  if (!controller_) {
    const auto* message = error.localizedDescription.UTF8String;
    std::cerr << "USB host-controller registration failed: " << (message ? message : "unknown")
              << ". Provision com.apple.developer.usb.host-controller-interface.\n";
    return NO;
  }
  timer_ = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue_);
  dispatch_source_set_timer(timer_, DISPATCH_TIME_NOW, 5 * NSEC_PER_MSEC, NSEC_PER_MSEC);
  dispatch_source_set_event_handler(timer_, ^{
    if (stopped_ || polling_) return;
    if (rebooting_) {
      if (std::chrono::steady_clock::now() >= reboot_deadline_) { [self stop]; return; }
      if (reboot_prepared_ && !device_) {
        NSError* port_error = nil;
        auto* port = [controller_ getPortStateMachineForPort:1 error:&port_error];
        if (!port || port_error) { [self stop]; return; }
        if (port.powered) {
          port.connected = YES;
          rebooting_ = false;
          std::cerr << "Software composite device reenumerated.\n";
        }
      }
      return;
    }
    polling_ = true;
    const bool pending = [busy_ containsObject:@(swpk::usb::kCcidIn)] || [busy_ containsObject:@(swpk::usb::kFidoIn)];
    dispatch_async(worker_, ^{
      bool failed = false, reboot = false;
      try {
        backend_->forward();
        reboot = backend_->poll_reboot() && backend_->reboot_ready(pending);
      } catch (...) { failed = true; }
      dispatch_async(queue_, ^{
        polling_ = false;
        if (failed) { [self stop]; return; }
        if (reboot) { [self beginReboot]; return; }
        for (IOUSBHostCIEndpointStateMachine* endpoint in endpoints_.allValues) [self pump:endpoint];
      });
    });
  });
  dispatch_resume(timer_);
  return YES;
}
- (void)beginReboot {
  NSError* error = nil;
  auto* port = [controller_ getPortStateMachineForPort:1 error:&error];
  if (!port || error) { [self stop]; return; }
  rebooting_ = true; reboot_prepared_ = false; ++epoch_;
  reboot_deadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  [busy_ removeAllObjects]; control_ = {};
  port.connected = NO;
  dispatch_async(worker_, ^{
    bool failed = false;
    try { backend_->apply_reboot(); } catch (...) { failed = true; }
    dispatch_async(queue_, ^{
      if (failed) { [self stop]; return; }
      reboot_prepared_ = true;
    });
  });
}
- (void)stop {
  if (stopped_) return;
  stopped_ = true; ++epoch_;
  if (timer_) dispatch_source_cancel(timer_);
  [controller_ destroy]; [endpoints_ removeAllObjects]; [busy_ removeAllObjects];
  std::cerr << "Software composite controller disconnected.\n";
  dispatch_async(queue_, ^{ exit(1); });
}
- (void)command:(IOUSBHostCIMessage)command {
  if (stopped_) return;
  NSError* error = nil;
  const auto type = command.control & IOUSBHostCIMessageControlType;
  if (type >= IOUSBHostCIMessageTypeControllerPowerOn && type <= IOUSBHostCIMessageTypeControllerFrameNumber) {
    auto* machine = controller_.controllerStateMachine;
    if (![machine inspectCommand:&command error:&error]) { [self stop]; return; }
    if (type == IOUSBHostCIMessageTypeControllerFrameNumber) {
      mach_timebase_info_data_t timebase{}; mach_timebase_info(&timebase);
      const auto now = mach_absolute_time();
      const auto ns = (now - start_time_) * timebase.numer / timebase.denom;
      const auto frame = ns / NSEC_PER_MSEC;
      const auto timestamp = start_time_ + (frame * NSEC_PER_MSEC) * timebase.denom / timebase.numer;
      [machine respondToCommand:&command status:IOUSBHostCIMessageStatusSuccess frame:frame timestamp:timestamp error:&error];
    } else [machine respondToCommand:&command status:IOUSBHostCIMessageStatusSuccess error:&error];
  } else if (type >= IOUSBHostCIMessageTypePortPowerOn && type <= IOUSBHostCIMessageTypePortStatus) {
    auto* port = [controller_ getPortStateMachineForCommand:&command error:&error];
    if (!port || ![port inspectCommand:&command error:&error]) { [self stop]; return; }
    if (type == IOUSBHostCIMessageTypePortPowerOn) port.powered = YES;
    if (type == IOUSBHostCIMessageTypePortPowerOff) { port.connected = NO; port.powered = NO; }
    const auto state = type == IOUSBHostCIMessageTypePortSuspend ? IOUSBHostCILinkStateU3 :
        (type == IOUSBHostCIMessageTypePortDisable || type == IOUSBHostCIMessageTypePortPowerOff)
          ? IOUSBHostCILinkStateDisabled : IOUSBHostCILinkStateU0;
    const auto speed = type == IOUSBHostCIMessageTypePortPowerOff ? IOUSBHostCIDeviceSpeedNone : IOUSBHostCIDeviceSpeedFull;
    [port updateLinkState:state speed:speed inhibitLinkStateChange:YES error:&error];
    if (type == IOUSBHostCIMessageTypePortPowerOn && !rebooting_) port.connected = YES;
    if (type == IOUSBHostCIMessageTypePortReset || type == IOUSBHostCIMessageTypePortPowerOff) {
      ++epoch_; [busy_ removeAllObjects]; control_ = {};
      dispatch_async(worker_, ^{ try { backend_->reset(); } catch (...) {} });
    }
    if (type == IOUSBHostCIMessageTypePortSuspend || type == IOUSBHostCIMessageTypePortResume) {
      // Finish the card lifecycle on the serial backend queue before
      // acknowledging the port command. Keep committed endpoint transfers.
      dispatch_async(worker_, ^{
        bool failed = false;
        try {
          if (type == IOUSBHostCIMessageTypePortSuspend) backend_->suspend();
          else backend_->resume();
        } catch (...) { failed = true; }
        dispatch_async(queue_, ^{
          if (stopped_) return;
          if (failed) { [self stop]; return; }
          auto reply = command;
          NSError* reply_error = nil;
          if (![port respondToCommand:&reply status:IOUSBHostCIMessageStatusSuccess error:&reply_error] || reply_error)
            [self stop];
        });
      });
      if (error) [self stop];
      return;
    }
    [port respondToCommand:&command status:IOUSBHostCIMessageStatusSuccess error:&error];
  } else if (type == IOUSBHostCIMessageTypeDeviceCreate) {
    // One directly attached synthetic device at root port 1, no hubs/routes.
    if (device_ || command.data0 != 1) { [self stop]; return; }
    device_ = [[IOUSBHostCIDeviceStateMachine alloc] initWithInterface:controller_ command:&command error:&error];
    if (!device_) { [self stop]; return; }
    [device_ respondToCommand:&command status:IOUSBHostCIMessageStatusSuccess deviceAddress:1 error:&error];
  } else if (type >= IOUSBHostCIMessageTypeDeviceDestroy && type <= IOUSBHostCIMessageTypeDeviceUpdate) {
    if (!device_ || ![device_ inspectCommand:&command error:&error]) { [self stop]; return; }
    [device_ respondToCommand:&command status:IOUSBHostCIMessageStatusSuccess error:&error];
    if (type == IOUSBHostCIMessageTypeDeviceDestroy) {
      ++epoch_; [endpoints_ removeAllObjects]; [busy_ removeAllObjects]; device_ = nil; control_ = {};
      dispatch_async(worker_, ^{ try { backend_->reset(); } catch (...) {} });
    }
  } else if (type >= IOUSBHostCIMessageTypeEndpointCreate && type <= IOUSBHostCIMessageTypeEndpointSetNextTransfer) {
    const auto address = command.data0 & IOUSBHostCICommandMessageData0DeviceAddress;
    const auto ep = (command.data0 & IOUSBHostCICommandMessageData0EndpointAddress) >> IOUSBHostCICommandMessageData0EndpointAddressPhase;
    NSNumber* key = @(ep);
    if (address != 1 || ep > 255 || !backend_->model->endpoint_exists(static_cast<std::uint8_t>(ep))) { [self stop]; return; }
    auto* endpoint = endpoints_[key];
    if (type == IOUSBHostCIMessageTypeEndpointCreate) {
      if (endpoint) { [self stop]; return; }
      endpoint = [[IOUSBHostCIEndpointStateMachine alloc] initWithInterface:controller_ command:&command error:&error];
      if (endpoint) endpoints_[key] = endpoint;
    }
    if (!endpoint || ![endpoint inspectCommand:&command error:&error]) { [self stop]; return; }
    // Stop accessing shared transfer buffers before the framework changes state.
    ++endpoint_generation_[ep]; [busy_ removeObject:key];
    [endpoint respondToCommand:&command status:IOUSBHostCIMessageStatusSuccess error:&error];
    if (type == IOUSBHostCIMessageTypeEndpointDestroy) [endpoints_ removeObjectForKey:key];
  } else { [self stop]; return; }
  if (error) [self stop];
}
- (void)doorbell:(IOUSBHostCIDoorbell)doorbell {
  if (stopped_) return;
  const auto address = (doorbell & IOUSBHostCIDoorbellDeviceAddress) >> IOUSBHostCIDoorbellDeviceAddressPhase;
  const auto ep = (doorbell & IOUSBHostCIDoorbellEndpointAddress) >> IOUSBHostCIDoorbellEndpointAddressPhase;
  auto* endpoint = endpoints_[@(ep)]; NSError* error = nil;
  if (address != 1 || !endpoint || ![endpoint processDoorbell:doorbell error:&error]) return;
  [self pump:endpoint];
}
- (void)pump:(IOUSBHostCIEndpointStateMachine*)endpoint {
  NSNumber* key = @(endpoint.endpointAddress);
  if (stopped_ || rebooting_ || [busy_ containsObject:key] || endpoint.endpointState != IOUSBHostCIEndpointStateActive) return;
  const auto* message = endpoint.currentTransferMessage;
  if (!message || !(message->control & IOUSBHostCIMessageControlValid)) return;
  const auto type = message->control & IOUSBHostCIMessageControlType;
  const auto ep = static_cast<std::uint8_t>(endpoint.endpointAddress);
  const auto epoch = epoch_;
  const auto generation = endpoint_generation_[ep];
  const auto capacity = static_cast<std::size_t>(message->data0 & IOUSBHostCINormalTransferData0Length);
  if (capacity > 32786 && type == IOUSBHostCIMessageTypeNormalTransfer) { [self stop]; return; }
  const auto incoming = (ep & 0x80) != 0;
  auto status = IOUSBHostCIMessageStatusSuccess;
  std::size_t transferred{};
  if (type == IOUSBHostCIMessageTypeSetupTransfer && (ep & 15) == 0) {
    const auto value = message->data1;
    std::array<std::uint8_t,8> setup{};
    for (std::size_t i = 0; i < setup.size(); ++i) setup[i] = static_cast<std::uint8_t>(value >> (8*i));
    control_ = {}; control_.setup = Setup::decode(setup);
    transferred = 8;
  } else if (type == IOUSBHostCIMessageTypeStatusTransfer && (ep & 15) == 0) {
    status = control_.stalled ? IOUSBHostCIMessageStatusStallError : IOUSBHostCIMessageStatusSuccess;
    control_ = {};
  } else if (type == IOUSBHostCIMessageTypeNormalTransfer) {
    void* buffer = reinterpret_cast<void*>(static_cast<std::uintptr_t>(message->data1));
    if (!buffer && capacity) { [self stop]; return; }
    Bytes output;
    const bool control = (ep & 15) == 0;
    if (control && !(control_.setup.type & 0x80)) {
      const auto* bytes = static_cast<const std::uint8_t*>(buffer);
      if (control_.output.size() + capacity > control_.setup.length) { [self stop]; return; }
      if (capacity) control_.output.insert(control_.output.end(), bytes, bytes + capacity);
    } else if (!control && !incoming) {
      const auto* bytes = static_cast<const std::uint8_t*>(buffer);
      if (capacity) output.assign(bytes, bytes + capacity);
    }
    const auto flow = control_;
    [busy_ addObject:key];
    dispatch_async(worker_, ^{
      bool failed = false, pending = false;
      auto result_status = IOUSBHostCIMessageStatusSuccess;
      Bytes data;
      ControlFlow evaluated = flow;
      std::size_t count = capacity;
      try {
        if (control) {
          if (!evaluated.evaluated && ((evaluated.setup.type & 0x80) || evaluated.output.size() == evaluated.setup.length)) {
            auto response = backend_->model->control(evaluated.setup, evaluated.output);
            evaluated.evaluated = true; evaluated.stalled = response.stalled; evaluated.input = std::move(response.data);
          }
          if (evaluated.stalled) result_status = IOUSBHostCIMessageStatusStallError;
          if (evaluated.setup.type & 0x80) {
            const auto remaining = evaluated.input.size() - evaluated.offset;
            count = std::min(capacity, remaining);
            data.assign(evaluated.input.begin() + static_cast<std::ptrdiff_t>(evaluated.offset),
                        evaluated.input.begin() + static_cast<std::ptrdiff_t>(evaluated.offset + count));
            evaluated.offset += count;
          }
        } else if (incoming) {
          if (!backend_->model->configured() || backend_->model->endpoint_halted(ep))
            result_status = IOUSBHostCIMessageStatusStallError;
          else {
            auto response = backend_->model->input(ep, capacity);
            if (response) { data = std::move(*response); count = data.size(); }
            else pending = true;
          }
        } else if (!backend_->model->output(ep, output)) result_status = IOUSBHostCIMessageStatusStallError;
        backend_->forward();
      } catch (...) { failed = true; }
      dispatch_async(queue_, ^{
        if (failed) { [self stop]; return; }
        if (stopped_ || epoch != epoch_ || generation != endpoint_generation_[ep] || endpoints_[key] != endpoint ||
            endpoint.endpointState != IOUSBHostCIEndpointStateActive || endpoint.currentTransferMessage != message) return;
        [busy_ removeObject:key];
        if (pending) return;
        if (control) control_ = evaluated;
        if (!data.empty()) std::memcpy(buffer, data.data(), data.size());
        NSError* error = nil;
        [endpoint enqueueTransferCompletionForMessage:message status:result_status
            transferLength:result_status == IOUSBHostCIMessageStatusSuccess ? count : 0 error:&error];
        if (error) { [self stop]; return; }
        [self pump:endpoint];
      });
    });
    return;
  } else { [self stop]; return; }
  // Zero-data controls are evaluated before their status stage, off the controller queue.
  if (type == IOUSBHostCIMessageTypeSetupTransfer && !control_.setup.length) {
    const auto setup = control_.setup;
    [busy_ addObject:key];
    dispatch_async(worker_, ^{
      bool failed = false; swpk::usb::ControlResult response;
      try { response = backend_->model->control(setup); backend_->forward(); } catch (...) { failed = true; }
      dispatch_async(queue_, ^{
        if (failed) { [self stop]; return; }
        if (stopped_ || epoch != epoch_ || generation != endpoint_generation_[ep] || endpoints_[key] != endpoint ||
            endpoint.endpointState != IOUSBHostCIEndpointStateActive || endpoint.currentTransferMessage != message) return;
        [busy_ removeObject:key];
        control_.evaluated = true; control_.stalled = response.stalled;
        NSError* error = nil;
        [endpoint enqueueTransferCompletionForMessage:message status:status transferLength:transferred error:&error];
        if (error) [self stop]; else [self pump:endpoint];
      });
    });
  } else {
    NSError* error = nil;
    [endpoint enqueueTransferCompletionForMessage:message status:status transferLength:transferred error:&error];
    if (error) [self stop]; else dispatch_async(queue_, ^{ [self pump:endpoint]; });
  }
}
@end

int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--help") {
    std::cout << "ske-usbd --card-socket PATH --fido-socket PATH [--yubico-usb-ids] [--wire-test]\n"
              << "Native synthetic USB FIDO/CCID/OTP requires provisioned host-controller entitlement.\n"
              << "--yubico-usb-ids uses public SDK matching IDs; the product still identifies software emulation.\n"
              << "--wire-test accepts control/out/in/reset lines and creates no OS devices.\n";
    return 0;
  }
  if (argc < 5 || argc > 7 || std::string(argv[1]) != "--card-socket" || std::string(argv[3]) != "--fido-socket") return 2;
  bool test = false, compatibility_ids = false;
  for (int i = 5; i < argc; ++i) {
    const std::string flag = argv[i];
    if (flag == "--wire-test" && !test) test = true;
    else if (flag == "--yubico-usb-ids" && !compatibility_ids) compatibility_ids = true;
    else return 2;
  }
  @autoreleasepool {
    try {
      auto backend = std::make_shared<Backend>(argv[2],argv[4],compatibility_ids);
      if (test) { wire_test(*backend); return 0; }
      SkeUSBHost* host = [SkeUSBHost new]; host->backend_ = std::move(backend);
      if (![host start]) return 3;
      dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
        std::string line;
        while (std::getline(std::cin,line)) {
          std::istringstream input(line); std::string command, duration; input >> command >> duration;
          if (command != "hold") continue;
          dispatch_async(host->worker_, ^{
            try { host->backend_->hold(duration); } catch (...) { std::cerr << "Hold request rejected.\n"; }
          });
        }
      });
      signal(SIGINT, SIG_IGN); signal(SIGTERM, SIG_IGN);
      for (const auto signum : {SIGINT,SIGTERM}) {
        auto source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, static_cast<uintptr_t>(signum), 0, host->queue_);
        dispatch_source_set_event_handler(source, ^{ [host stop]; exit(0); }); dispatch_resume(source);
        // Dispatch owns the source until process exit via this handler capture.
        dispatch_source_set_cancel_handler(source, ^{ (void)source; });
      }
      dispatch_main();
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1;
    } catch (const swpk::pcsc::WireError&) { std::cerr << "Card service unavailable.\n"; return 1; }
  }
}

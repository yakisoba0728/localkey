// Read public metadata and cached configuration descriptors without opening,
// seizing, resetting or configuring the physical USB device. No serial strings.
#import <Foundation/Foundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>

static NSNumber* property(io_service_t service, const char* key) {
  NSString* name = [NSString stringWithUTF8String:key];
  id value = CFBridgingRelease(IORegistryEntryCreateCFProperty(service,
      (__bridge CFStringRef)name, kCFAllocatorDefault, 0));
  return [value isKindOfClass:NSNumber.class] ? value : nil;
}
static NSString* hex(const void* bytes, std::size_t length) {
  const auto* data = static_cast<const unsigned char*>(bytes);
  NSMutableString* out = [NSMutableString stringWithCapacity:length * 2];
  for (std::size_t i = 0; i < length; ++i) [out appendFormat:@"%02x", data[i]];
  return out;
}
static NSData* report_descriptor(io_registry_entry_t entry, unsigned depth = 0) {
  if (depth > 8) return nil;
  id value = CFBridgingRelease(IORegistryEntryCreateCFProperty(entry,
      CFSTR("ReportDescriptor"), kCFAllocatorDefault, 0));
  if ([value isKindOfClass:NSData.class] && [value length] <= 1024) return value;
  io_iterator_t children{};
  if (IORegistryEntryGetChildIterator(entry, kIOServicePlane, &children)) return nil;
  io_registry_entry_t child{};
  NSData* result = nil;
  while ((child = IOIteratorNext(children))) {
    result = report_descriptor(child, depth+1);
    IOObjectRelease(child);
    if (result) break;
  }
  IOObjectRelease(children);
  return result;
}
int main(int argc, const char* argv[]) {
  @autoreleasepool {
    if (argc == 2 && !std::strcmp(argv[1], "--help")) {
      std::fputs("usage: ske-usb-observe --read-physical-reference\nReads only public registry/cached descriptors; never opens or resets the device.\n", stdout);
      return 0;
    }
    if (argc != 2 || std::strcmp(argv[1], "--read-physical-reference")) {
      std::fputs("usage: observe_usb --read-physical-reference\n", stderr);
      return 2;
    }
    io_iterator_t iterator{};
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOUSBHostDevice"), &iterator))
      return 3;
    io_service_t selected{}, service{};
    unsigned count{};
    while ((service = IOIteratorNext(iterator))) {
      if (property(service, "idVendor").unsignedIntValue == 0x1050 &&
          property(service, "idProduct").unsignedIntValue == 0x0406) {
        ++count;
        if (!selected) { selected = service; continue; }
      }
      IOObjectRelease(service);
    }
    IOObjectRelease(iterator);
    if (count != 1) {
      if (selected) IOObjectRelease(selected);
      std::fputs("expected exactly one reference 1050:0406 device\n", stderr);
      return 4;
    }
    NSMutableDictionary* result = [@{@"source": @"physical USB public registry and cached configuration",
      @"captured_utc": [[NSISO8601DateFormatter new] stringFromDate:NSDate.date],
      @"device_opened": @NO, @"device_reset_or_configured": @NO,
      @"credentials_accessed_or_changed": @NO, @"serial_strings_read": @NO} mutableCopy];
    NSMutableDictionary* fields = [NSMutableDictionary new];
    for (const auto* key : {"idVendor", "idProduct", "bcdUSB", "bcdDevice", "bDeviceClass",
                           "bDeviceSubClass", "bDeviceProtocol", "bMaxPacketSize0", "bNumConfigurations"}) {
      if (NSNumber* value = property(selected, key)) fields[[NSString stringWithUTF8String:key]] = value;
    }
    result[@"device_fields"] = fields;
    if (NSData* report = report_descriptor(selected))
      result[@"hid_report_descriptor_hex"] = hex(report.bytes, report.length);
    IOCFPlugInInterface** plugin{};
    SInt32 score{};
    auto code = IOCreatePlugInInterfaceForService(selected, kIOUSBDeviceUserClientTypeID,
        kIOCFPlugInInterfaceID, &plugin, &score);
    IOUSBDeviceInterface942** device{};
    if (!code && plugin) {
      const auto queried = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID942),
          reinterpret_cast<LPVOID*>(&device));
      (*plugin)->Release(plugin);
      if (queried || !device) code = kIOReturnUnsupported;
    }
    if (!code && device) {
      // The SDK expressly permits these functions without USBDeviceOpen.
      // Do not use DeviceRequest/USBDeviceOpen/SetConfiguration/ResetDevice.
      IOUSBConfigurationDescriptorPtr descriptor{};
      code = (*device)->GetConfigurationDescriptorPtr(device, 0, &descriptor);
      if (!code && descriptor && descriptor->bLength == 9 && descriptor->bDescriptorType == 2) {
        const auto length = static_cast<std::size_t>(USBToHostWord(descriptor->wTotalLength));
        if (length >= 9 && length <= 4096) result[@"configuration_descriptor_hex"] = hex(descriptor, length);
        else code = kIOReturnBadArgument;
      } else if (!code) code = kIOReturnNotFound;
      (*device)->Release(device);
    }
    result[@"configuration_available"] = @(result[@"configuration_descriptor_hex"] != nil);
    if (code) result[@"configuration_error_code"] = @(static_cast<unsigned>(code));
    IOObjectRelease(selected);
    NSData* json = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:nil];
    if (!json) return 5;
    std::fwrite(json.bytes, 1, json.length, stdout); std::fputc('\n', stdout);
    return 0;
  }
}

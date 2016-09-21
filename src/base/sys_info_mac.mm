// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/sys_info.h"

#include <ApplicationServices/ApplicationServices.h>
#include <CoreServices/CoreServices.h>
#import <Foundation/Foundation.h>
#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include "base/logging.h"
#include "base/mac/mac_util.h"
#include "base/mac/scoped_mach_port.h"
#import "base/mac/sdk_forward_declarations.h"
#include "base/macros.h"
#include "base/strings/stringprintf.h"

namespace base {

// static
std::string SysInfo::OperatingSystemName() {
  return "Mac OS X";
}

// static
std::string SysInfo::OperatingSystemVersion() {
  int32_t major, minor, bugfix;
  OperatingSystemVersionNumbers(&major, &minor, &bugfix);
  return base::StringPrintf("%d.%d.%d", major, minor, bugfix);
}

// static
void SysInfo::OperatingSystemVersionNumbers(int32_t* major_version,
                                            int32_t* minor_version,
                                            int32_t* bugfix_version) {
  NSProcessInfo* processInfo = [NSProcessInfo processInfo];
  if ([processInfo respondsToSelector:@selector(operatingSystemVersion)]) {
    NSOperatingSystemVersion version = [processInfo operatingSystemVersion];
    *major_version = version.majorVersion;
    *minor_version = version.minorVersion;
    *bugfix_version = version.patchVersion;
  } else {
    // -[NSProcessInfo operatingSystemVersion] is documented available in 10.10.
    // It's also available via a private API since 10.9.2. For the remaining
    // cases in 10.9, rely on ::Gestalt(..). Since this code is only needed for
    // 10.9.0 and 10.9.1 and uses the recommended replacement thereafter,
    // suppress the warning for this fallback case.
    DCHECK(base::mac::IsOS10_9());
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    Gestalt(gestaltSystemVersionMajor,
            reinterpret_cast<SInt32*>(major_version));
    Gestalt(gestaltSystemVersionMinor,
            reinterpret_cast<SInt32*>(minor_version));
    Gestalt(gestaltSystemVersionBugFix,
            reinterpret_cast<SInt32*>(bugfix_version));
#pragma clang diagnostic pop
  }
}

// static
int64_t SysInfo::AmountOfPhysicalMemory() {
  struct host_basic_info hostinfo;
  mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
  base::mac::ScopedMachSendRight host(mach_host_self());
  int result = host_info(host.get(),
                         HOST_BASIC_INFO,
                         reinterpret_cast<host_info_t>(&hostinfo),
                         &count);
  if (result != KERN_SUCCESS) {
    NOTREACHED();
    return 0;
  }
  DCHECK_EQ(HOST_BASIC_INFO_COUNT, count);
  return static_cast<int64_t>(hostinfo.max_mem);
}

// static
int64_t SysInfo::AmountOfAvailablePhysicalMemory() {
  base::mac::ScopedMachSendRight host(mach_host_self());
  vm_statistics_data_t vm_info;
  mach_msg_type_number_t count = HOST_VM_INFO_COUNT;

  if (host_statistics(host.get(),
                      HOST_VM_INFO,
                      reinterpret_cast<host_info_t>(&vm_info),
                      &count) != KERN_SUCCESS) {
    NOTREACHED();
    return 0;
  }

  return static_cast<int64_t>(vm_info.free_count - vm_info.speculative_count) *
         PAGE_SIZE;
}

// static
std::string SysInfo::CPUModelName() {
  char name[256];
  size_t len = arraysize(name);
  if (sysctlbyname("machdep.cpu.brand_string", &name, &len, NULL, 0) == 0)
    return name;
  return std::string();
}

std::string SysInfo::HardwareModelName() {
  char model[256];
  size_t len = sizeof(model);
  if (sysctlbyname("hw.model", model, &len, NULL, 0) == 0)
    return std::string(model, 0, len);
  return std::string();
}

}  // namespace base

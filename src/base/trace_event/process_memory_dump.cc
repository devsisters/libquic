// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/process_memory_dump.h"

#include <errno.h>

#include <vector>

#include "base/memory/ptr_util.h"
#include "base/process/process_metrics.h"
#include "base/strings/stringprintf.h"
#include "base/trace_event/heap_profiler_heap_dump_writer.h"
#include "base/trace_event/memory_infra_background_whitelist.h"
#include "base/trace_event/process_memory_totals.h"
#include "base/trace_event/trace_event_argument.h"
#include "build/build_config.h"

#if defined(OS_IOS)
#include <sys/sysctl.h>
#endif

#if defined(OS_POSIX)
#include <sys/mman.h>
#endif

#if defined(OS_WIN)
#include <Psapi.h>
#endif

namespace base {
namespace trace_event {

namespace {

const char kEdgeTypeOwnership[] = "ownership";

std::string GetSharedGlobalAllocatorDumpName(
    const MemoryAllocatorDumpGuid& guid) {
  return "global/" + guid.ToString();
}

#if defined(COUNT_RESIDENT_BYTES_SUPPORTED)
size_t GetSystemPageCount(size_t mapped_size, size_t page_size) {
  return (mapped_size + page_size - 1) / page_size;
}
#endif

}  // namespace

// static
bool ProcessMemoryDump::is_black_hole_non_fatal_for_testing_ = false;

#if defined(COUNT_RESIDENT_BYTES_SUPPORTED)
// static
size_t ProcessMemoryDump::GetSystemPageSize() {
#if defined(OS_IOS)
  // On iOS, getpagesize() returns the user page sizes, but for allocating
  // arrays for mincore(), kernel page sizes is needed. sysctlbyname() should
  // be used for this. Refer to crbug.com/542671 and Apple rdar://23651782
  int pagesize;
  size_t pagesize_len;
  int status = sysctlbyname("vm.pagesize", NULL, &pagesize_len, nullptr, 0);
  if (!status && pagesize_len == sizeof(pagesize)) {
    if (!sysctlbyname("vm.pagesize", &pagesize, &pagesize_len, nullptr, 0))
      return pagesize;
  }
  LOG(ERROR) << "sysctlbyname(\"vm.pagesize\") failed.";
  // Falls back to getpagesize() although it may be wrong in certain cases.
#endif  // defined(OS_IOS)
  return base::GetPageSize();
}

// static
size_t ProcessMemoryDump::CountResidentBytes(void* start_address,
                                             size_t mapped_size) {
  const size_t page_size = GetSystemPageSize();
  const uintptr_t start_pointer = reinterpret_cast<uintptr_t>(start_address);
  DCHECK_EQ(0u, start_pointer % page_size);

  size_t offset = 0;
  size_t total_resident_size = 0;
  bool failure = false;

  // An array as large as number of pages in memory segment needs to be passed
  // to the query function. To avoid allocating a large array, the given block
  // of memory is split into chunks of size |kMaxChunkSize|.
  const size_t kMaxChunkSize = 8 * 1024 * 1024;
  size_t max_vec_size =
      GetSystemPageCount(std::min(mapped_size, kMaxChunkSize), page_size);
#if defined(OS_MACOSX) || defined(OS_IOS)
  std::unique_ptr<char[]> vec(new char[max_vec_size]);
#elif defined(OS_WIN)
  std::unique_ptr<PSAPI_WORKING_SET_EX_INFORMATION[]> vec(
      new PSAPI_WORKING_SET_EX_INFORMATION[max_vec_size]);
#elif defined(OS_POSIX)
  std::unique_ptr<unsigned char[]> vec(new unsigned char[max_vec_size]);
#endif

  while (offset < mapped_size) {
    uintptr_t chunk_start = (start_pointer + offset);
    const size_t chunk_size = std::min(mapped_size - offset, kMaxChunkSize);
    const size_t page_count = GetSystemPageCount(chunk_size, page_size);
    size_t resident_page_count = 0;

#if defined(OS_MACOSX) || defined(OS_IOS)
    // mincore in MAC does not fail with EAGAIN.
    failure =
        !!mincore(reinterpret_cast<void*>(chunk_start), chunk_size, vec.get());
    for (size_t i = 0; i < page_count; i++)
      resident_page_count += vec[i] & MINCORE_INCORE ? 1 : 0;
#elif defined(OS_WIN)
    for (size_t i = 0; i < page_count; i++) {
      vec[i].VirtualAddress =
          reinterpret_cast<void*>(chunk_start + i * page_size);
    }
    DWORD vec_size = static_cast<DWORD>(
        page_count * sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
    failure = !QueryWorkingSetEx(GetCurrentProcess(), vec.get(), vec_size);

    for (size_t i = 0; i < page_count; i++)
      resident_page_count += vec[i].VirtualAttributes.Valid;
#elif defined(OS_POSIX)
    int error_counter = 0;
    int result = 0;
    // HANDLE_EINTR tries for 100 times. So following the same pattern.
    do {
      result =
          mincore(reinterpret_cast<void*>(chunk_start), chunk_size, vec.get());
    } while (result == -1 && errno == EAGAIN && error_counter++ < 100);
    failure = !!result;

    for (size_t i = 0; i < page_count; i++)
      resident_page_count += vec[i] & 1;
#endif

    if (failure)
      break;

    total_resident_size += resident_page_count * page_size;
    offset += kMaxChunkSize;
  }

  DCHECK(!failure);
  if (failure) {
    total_resident_size = 0;
    LOG(ERROR) << "CountResidentBytes failed. The resident size is invalid";
  }
  return total_resident_size;
}
#endif  // defined(COUNT_RESIDENT_BYTES_SUPPORTED)

ProcessMemoryDump::ProcessMemoryDump(
    scoped_refptr<MemoryDumpSessionState> session_state,
    const MemoryDumpArgs& dump_args)
    : has_process_totals_(false),
      has_process_mmaps_(false),
      session_state_(std::move(session_state)),
      dump_args_(dump_args) {}

ProcessMemoryDump::~ProcessMemoryDump() {}

MemoryAllocatorDump* ProcessMemoryDump::CreateAllocatorDump(
    const std::string& absolute_name) {
  return AddAllocatorDumpInternal(
      MakeUnique<MemoryAllocatorDump>(absolute_name, this));
}

MemoryAllocatorDump* ProcessMemoryDump::CreateAllocatorDump(
    const std::string& absolute_name,
    const MemoryAllocatorDumpGuid& guid) {
  return AddAllocatorDumpInternal(
      MakeUnique<MemoryAllocatorDump>(absolute_name, this, guid));
}

MemoryAllocatorDump* ProcessMemoryDump::AddAllocatorDumpInternal(
    std::unique_ptr<MemoryAllocatorDump> mad) {
  // In background mode return the black hole dump, if invalid dump name is
  // given.
  if (dump_args_.level_of_detail == MemoryDumpLevelOfDetail::BACKGROUND &&
      !IsMemoryAllocatorDumpNameWhitelisted(mad->absolute_name())) {
    return GetBlackHoleMad();
  }

  auto insertion_result = allocator_dumps_.insert(
      std::make_pair(mad->absolute_name(), std::move(mad)));
  MemoryAllocatorDump* inserted_mad = insertion_result.first->second.get();
  DCHECK(insertion_result.second) << "Duplicate name: "
                                  << inserted_mad->absolute_name();
  return inserted_mad;
}

MemoryAllocatorDump* ProcessMemoryDump::GetAllocatorDump(
    const std::string& absolute_name) const {
  auto it = allocator_dumps_.find(absolute_name);
  if (it != allocator_dumps_.end())
    return it->second.get();
  if (black_hole_mad_)
    return black_hole_mad_.get();
  return nullptr;
}

MemoryAllocatorDump* ProcessMemoryDump::GetOrCreateAllocatorDump(
    const std::string& absolute_name) {
  MemoryAllocatorDump* mad = GetAllocatorDump(absolute_name);
  return mad ? mad : CreateAllocatorDump(absolute_name);
}

MemoryAllocatorDump* ProcessMemoryDump::CreateSharedGlobalAllocatorDump(
    const MemoryAllocatorDumpGuid& guid) {
  // Global dumps are disabled in background mode.
  if (dump_args_.level_of_detail == MemoryDumpLevelOfDetail::BACKGROUND)
    return GetBlackHoleMad();

  // A shared allocator dump can be shared within a process and the guid could
  // have been created already.
  MemoryAllocatorDump* mad = GetSharedGlobalAllocatorDump(guid);
  if (mad) {
    // The weak flag is cleared because this method should create a non-weak
    // dump.
    mad->clear_flags(MemoryAllocatorDump::Flags::WEAK);
    return mad;
  }
  return CreateAllocatorDump(GetSharedGlobalAllocatorDumpName(guid), guid);
}

MemoryAllocatorDump* ProcessMemoryDump::CreateWeakSharedGlobalAllocatorDump(
    const MemoryAllocatorDumpGuid& guid) {
  // Global dumps are disabled in background mode.
  if (dump_args_.level_of_detail == MemoryDumpLevelOfDetail::BACKGROUND)
    return GetBlackHoleMad();

  MemoryAllocatorDump* mad = GetSharedGlobalAllocatorDump(guid);
  if (mad)
    return mad;
  mad = CreateAllocatorDump(GetSharedGlobalAllocatorDumpName(guid), guid);
  mad->set_flags(MemoryAllocatorDump::Flags::WEAK);
  return mad;
}

MemoryAllocatorDump* ProcessMemoryDump::GetSharedGlobalAllocatorDump(
    const MemoryAllocatorDumpGuid& guid) const {
  return GetAllocatorDump(GetSharedGlobalAllocatorDumpName(guid));
}

void ProcessMemoryDump::DumpHeapUsage(
    const base::hash_map<base::trace_event::AllocationContext,
        base::trace_event::AllocationMetrics>& metrics_by_context,
    base::trace_event::TraceEventMemoryOverhead& overhead,
    const char* allocator_name) {
  if (!metrics_by_context.empty()) {
    DCHECK_EQ(0ul, heap_dumps_.count(allocator_name));
    std::unique_ptr<TracedValue> heap_dump = ExportHeapDump(
        metrics_by_context, *session_state());
    heap_dumps_[allocator_name] = std::move(heap_dump);
  }

  std::string base_name = base::StringPrintf("tracing/heap_profiler_%s",
                                             allocator_name);
  overhead.DumpInto(base_name.c_str(), this);
}

void ProcessMemoryDump::Clear() {
  if (has_process_totals_) {
    process_totals_.Clear();
    has_process_totals_ = false;
  }

  if (has_process_mmaps_) {
    process_mmaps_.Clear();
    has_process_mmaps_ = false;
  }

  allocator_dumps_.clear();
  allocator_dumps_edges_.clear();
  heap_dumps_.clear();
}

void ProcessMemoryDump::TakeAllDumpsFrom(ProcessMemoryDump* other) {
  DCHECK(!other->has_process_totals() && !other->has_process_mmaps());

  // Moves the ownership of all MemoryAllocatorDump(s) contained in |other|
  // into this ProcessMemoryDump, checking for duplicates.
  for (auto& it : other->allocator_dumps_)
    AddAllocatorDumpInternal(std::move(it.second));
  other->allocator_dumps_.clear();

  // Move all the edges.
  allocator_dumps_edges_.insert(allocator_dumps_edges_.end(),
                                other->allocator_dumps_edges_.begin(),
                                other->allocator_dumps_edges_.end());
  other->allocator_dumps_edges_.clear();

  for (auto& it : other->heap_dumps_) {
    DCHECK_EQ(0ul, heap_dumps_.count(it.first));
    heap_dumps_.insert(std::make_pair(it.first, std::move(it.second)));
  }
  other->heap_dumps_.clear();
}

void ProcessMemoryDump::AsValueInto(TracedValue* value) const {
  if (has_process_totals_) {
    value->BeginDictionary("process_totals");
    process_totals_.AsValueInto(value);
    value->EndDictionary();
  }

  if (has_process_mmaps_) {
    value->BeginDictionary("process_mmaps");
    process_mmaps_.AsValueInto(value);
    value->EndDictionary();
  }

  if (allocator_dumps_.size() > 0) {
    value->BeginDictionary("allocators");
    for (const auto& allocator_dump_it : allocator_dumps_)
      allocator_dump_it.second->AsValueInto(value);
    value->EndDictionary();
  }

  if (heap_dumps_.size() > 0) {
    value->BeginDictionary("heaps");
    for (const auto& name_and_dump : heap_dumps_)
      value->SetValueWithCopiedName(name_and_dump.first, *name_and_dump.second);
    value->EndDictionary();  // "heaps"
  }

  value->BeginArray("allocators_graph");
  for (const MemoryAllocatorDumpEdge& edge : allocator_dumps_edges_) {
    value->BeginDictionary();
    value->SetString("source", edge.source.ToString());
    value->SetString("target", edge.target.ToString());
    value->SetInteger("importance", edge.importance);
    value->SetString("type", edge.type);
    value->EndDictionary();
  }
  value->EndArray();
}

void ProcessMemoryDump::AddOwnershipEdge(const MemoryAllocatorDumpGuid& source,
                                         const MemoryAllocatorDumpGuid& target,
                                         int importance) {
  allocator_dumps_edges_.push_back(
      {source, target, importance, kEdgeTypeOwnership});
}

void ProcessMemoryDump::AddOwnershipEdge(
    const MemoryAllocatorDumpGuid& source,
    const MemoryAllocatorDumpGuid& target) {
  AddOwnershipEdge(source, target, 0 /* importance */);
}

void ProcessMemoryDump::AddSuballocation(const MemoryAllocatorDumpGuid& source,
                                         const std::string& target_node_name) {
  // Do not create new dumps for suballocations in background mode.
  if (dump_args_.level_of_detail == MemoryDumpLevelOfDetail::BACKGROUND)
    return;

  std::string child_mad_name = target_node_name + "/__" + source.ToString();
  MemoryAllocatorDump* target_child_mad = CreateAllocatorDump(child_mad_name);
  AddOwnershipEdge(source, target_child_mad->guid());
}

MemoryAllocatorDump* ProcessMemoryDump::GetBlackHoleMad() {
  DCHECK(is_black_hole_non_fatal_for_testing_);
  if (!black_hole_mad_)
    black_hole_mad_.reset(new MemoryAllocatorDump("discarded", this));
  return black_hole_mad_.get();
}

}  // namespace trace_event
}  // namespace base

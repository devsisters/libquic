// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_infra_background_whitelist.h"

#include <ctype.h>
#include <string.h>

#include <string>

namespace base {
namespace trace_event {
namespace {

// The names of dump providers whitelisted for background tracing. Dump
// providers can be added here only if the background mode dump has very
// less performance and memory overhead.
const char* const kDumpProviderWhitelist[] = {
    "BlinkGC",
    "ChildDiscardableSharedMemoryManager",
    "DOMStorage",
    "HostDiscardableSharedMemoryManager",
    "IndexedDBBackingStore",
    "JavaHeap",
    "LeveldbValueStore",
    "Malloc",
    "PartitionAlloc",
    "ProcessMemoryMetrics",
    "Skia",
    "Sql",
    "V8Isolate",
    "WinHeap",
    nullptr  // End of list marker.
};

// A list of string names that are allowed for the memory allocator dumps in
// background mode.
const char* const kAllocatorDumpNameWhitelist[] = {
    "blink_gc",
    "blink_gc/allocated_objects",
    "discardable",
    "discardable/child_0x?",
    "dom_storage/0x?/cache_size",
    "dom_storage/session_storage_0x?",
    "java_heap",
    "java_heap/allocated_objects",
    "leveldb/index_db/0x?",
    "leveldb/value_store/Extensions.Database.Open.Settings/0x?",
    "leveldb/value_store/Extensions.Database.Open.Rules/0x?",
    "leveldb/value_store/Extensions.Database.Open.State/0x?",
    "leveldb/value_store/Extensions.Database.Open/0x?",
    "leveldb/value_store/Extensions.Database.Restore/0x?",
    "leveldb/value_store/Extensions.Database.Value.Restore/0x?",
    "malloc",
    "malloc/allocated_objects",
    "malloc/metadata_fragmentation_caches",
    "partition_alloc/allocated_objects",
    "partition_alloc/partitions",
    "partition_alloc/partitions/buffer",
    "partition_alloc/partitions/fast_malloc",
    "partition_alloc/partitions/layout",
    "skia/sk_glyph_cache",
    "skia/sk_resource_cache",
    "sqlite",
    "v8/isolate_0x?/heap_spaces",
    "v8/isolate_0x?/heap_spaces/code_space",
    "v8/isolate_0x?/heap_spaces/large_object_space",
    "v8/isolate_0x?/heap_spaces/map_space",
    "v8/isolate_0x?/heap_spaces/new_space",
    "v8/isolate_0x?/heap_spaces/old_space",
    "v8/isolate_0x?/heap_spaces/other_spaces",
    "v8/isolate_0x?/malloc",
    "v8/isolate_0x?/zapped_for_debug",
    "winheap",
    "winheap/allocated_objects",
    nullptr  // End of list marker.
};

const char* const* g_dump_provider_whitelist = kDumpProviderWhitelist;
const char* const* g_allocator_dump_name_whitelist =
    kAllocatorDumpNameWhitelist;

}  // namespace

bool IsMemoryDumpProviderWhitelisted(const char* mdp_name) {
  for (size_t i = 0; g_dump_provider_whitelist[i] != nullptr; ++i) {
    if (strcmp(mdp_name, g_dump_provider_whitelist[i]) == 0)
      return true;
  }
  return false;
}

bool IsMemoryAllocatorDumpNameWhitelisted(const std::string& name) {
  // Remove special characters, numbers (including hexadecimal which are marked
  // by '0x') from the given string.
  const size_t length = name.size();
  std::string stripped_str;
  stripped_str.reserve(length);
  bool parsing_hex = false;
  for (size_t i = 0; i < length; ++i) {
    if (parsing_hex && isxdigit(name[i]))
      continue;
    parsing_hex = false;
    if (i + 1 < length && name[i] == '0' && name[i + 1] == 'x') {
      parsing_hex = true;
      stripped_str.append("0x?");
      ++i;
    } else {
      stripped_str.push_back(name[i]);
    }
  }

  for (size_t i = 0; g_allocator_dump_name_whitelist[i] != nullptr; ++i) {
    if (stripped_str == g_allocator_dump_name_whitelist[i]) {
      return true;
    }
  }
  return false;
}

void SetDumpProviderWhitelistForTesting(const char* const* list) {
  g_dump_provider_whitelist = list;
}

void SetAllocatorDumpNameWhitelistForTesting(const char* const* list) {
  g_allocator_dump_name_whitelist = list;
}

}  // namespace trace_event
}  // namespace base

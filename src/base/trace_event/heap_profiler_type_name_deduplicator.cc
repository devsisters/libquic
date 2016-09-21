// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_type_name_deduplicator.h"

#include <stddef.h>
#include <stdlib.h>
#include <string>
#include <utility>

#include "base/json/string_escape.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/trace_event_memory_overhead.h"

namespace base {
namespace trace_event {

namespace {

// If |type_name| is file name then extract directory name. Or if |type_name| is
// category name, then disambiguate multple categories and remove
// "disabled-by-default" prefix if present.
StringPiece ExtractCategoryFromTypeName(const char* type_name) {
  StringPiece result(type_name);
  size_t last_seperator = result.find_last_of("\\/");

  // If |type_name| was a not a file path, the seperator will not be found, so
  // the whole type name is returned.
  if (last_seperator == StringPiece::npos) {
    // Use the first the category name if it has ",".
    size_t first_comma_position = result.find(',');
    if (first_comma_position != StringPiece::npos)
      result = result.substr(0, first_comma_position);
    if (result.starts_with(TRACE_DISABLED_BY_DEFAULT("")))
      result.remove_prefix(sizeof(TRACE_DISABLED_BY_DEFAULT("")) - 1);
    return result;
  }

  // Remove the file name from the path.
  result.remove_suffix(result.length() - last_seperator);

  // Remove the parent directory references.
  const char kParentDirectory[] = "..";
  const size_t kParentDirectoryLength = 3; // '../' or '..\'.
  while (result.starts_with(kParentDirectory)) {
    result.remove_prefix(kParentDirectoryLength);
  }
  return result;
}

}  // namespace

TypeNameDeduplicator::TypeNameDeduplicator() {
  // A null pointer has type ID 0 ("unknown type");
  type_ids_.insert(std::make_pair(nullptr, 0));
}

TypeNameDeduplicator::~TypeNameDeduplicator() {}

int TypeNameDeduplicator::Insert(const char* type_name) {
  auto result = type_ids_.insert(std::make_pair(type_name, 0));
  auto& elem = result.first;
  bool did_not_exist_before = result.second;

  if (did_not_exist_before) {
    // The type IDs are assigned sequentially and they are zero-based, so
    // |size() - 1| is the ID of the new element.
    elem->second = static_cast<int>(type_ids_.size() - 1);
  }

  return elem->second;
}

void TypeNameDeduplicator::AppendAsTraceFormat(std::string* out) const {
  out->append("{");  // Begin the type names dictionary.

  auto it = type_ids_.begin();
  std::string buffer;

  // Write the first entry manually; the null pointer must not be dereferenced.
  // (The first entry is the null pointer because a |std::map| is ordered.)
  it++;
  out->append("\"0\":\"[unknown]\"");

  for (; it != type_ids_.end(); it++) {
    // Type IDs in the trace are strings, write them as stringified keys of
    // a dictionary.
    SStringPrintf(&buffer, ",\"%d\":", it->second);

    // TODO(ssid): crbug.com/594803 the type name is misused for file name in
    // some cases.
    StringPiece type_info = ExtractCategoryFromTypeName(it->first);

    // |EscapeJSONString| appends, it does not overwrite |buffer|.
    bool put_in_quotes = true;
    EscapeJSONString(type_info, put_in_quotes, &buffer);
    out->append(buffer);
  }

  out->append("}");  // End the type names dictionary.
}

void TypeNameDeduplicator::EstimateTraceMemoryOverhead(
    TraceEventMemoryOverhead* overhead) {
  // The size here is only an estimate; it fails to take into account the size
  // of the tree nodes for the map, but as an estimate this should be fine.
  size_t map_size = type_ids_.size() * sizeof(std::pair<const char*, int>);

  overhead->Add("TypeNameDeduplicator",
                sizeof(TypeNameDeduplicator) + map_size);
}

}  // namespace trace_event
}  // namespace base

// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_stack_frame_deduplicator.h"

#include <inttypes.h>
#include <stddef.h>

#include <string>
#include <utility>

#include "base/strings/stringprintf.h"
#include "base/trace_event/trace_event_argument.h"
#include "base/trace_event/trace_event_memory_overhead.h"

namespace base {
namespace trace_event {

StackFrameDeduplicator::FrameNode::FrameNode(StackFrame frame,
                                             int parent_frame_index)
    : frame(frame), parent_frame_index(parent_frame_index) {}
StackFrameDeduplicator::FrameNode::FrameNode(const FrameNode& other) = default;
StackFrameDeduplicator::FrameNode::~FrameNode() {}

StackFrameDeduplicator::StackFrameDeduplicator() {}
StackFrameDeduplicator::~StackFrameDeduplicator() {}

int StackFrameDeduplicator::Insert(const StackFrame* beginFrame,
                                   const StackFrame* endFrame) {
  int frame_index = -1;
  std::map<StackFrame, int>* nodes = &roots_;

  // Loop through the frames, early out when a frame is null.
  for (const StackFrame* it = beginFrame; it != endFrame; it++) {
    StackFrame frame = *it;

    auto node = nodes->find(frame);
    if (node == nodes->end()) {
      // There is no tree node for this frame yet, create it. The parent node
      // is the node associated with the previous frame.
      FrameNode frame_node(frame, frame_index);

      // The new frame node will be appended, so its index is the current size
      // of the vector.
      frame_index = static_cast<int>(frames_.size());

      // Add the node to the trie so it will be found next time.
      nodes->insert(std::make_pair(frame, frame_index));

      // Append the node after modifying |nodes|, because the |frames_| vector
      // might need to resize, and this invalidates the |nodes| pointer.
      frames_.push_back(frame_node);
    } else {
      // A tree node for this frame exists. Look for the next one.
      frame_index = node->second;
    }

    nodes = &frames_[frame_index].children;
  }

  return frame_index;
}

void StackFrameDeduplicator::AppendAsTraceFormat(std::string* out) const {
  out->append("{");  // Begin the |stackFrames| dictionary.

  int i = 0;
  auto frame_node = begin();
  auto it_end = end();
  std::string stringify_buffer;

  while (frame_node != it_end) {
    // The |stackFrames| format is a dictionary, not an array, so the
    // keys are stringified indices. Write the index manually, then use
    // |TracedValue| to format the object. This is to avoid building the
    // entire dictionary as a |TracedValue| in memory.
    SStringPrintf(&stringify_buffer, "\"%d\":", i);
    out->append(stringify_buffer);

    std::unique_ptr<TracedValue> frame_node_value(new TracedValue);
    const StackFrame& frame = frame_node->frame;
    switch (frame.type) {
      case StackFrame::Type::TRACE_EVENT_NAME:
        frame_node_value->SetString(
            "name", static_cast<const char*>(frame.value));
        break;
      case StackFrame::Type::THREAD_NAME:
        SStringPrintf(&stringify_buffer,
                      "[Thread: %s]",
                      static_cast<const char*>(frame.value));
        frame_node_value->SetString("name", stringify_buffer);
        break;
      case StackFrame::Type::PROGRAM_COUNTER:
        SStringPrintf(&stringify_buffer,
                      "pc:%" PRIxPTR,
                      reinterpret_cast<uintptr_t>(frame.value));
        frame_node_value->SetString("name", stringify_buffer);
        break;
    }
    if (frame_node->parent_frame_index >= 0) {
      SStringPrintf(&stringify_buffer, "%d", frame_node->parent_frame_index);
      frame_node_value->SetString("parent", stringify_buffer);
    }
    frame_node_value->AppendAsTraceFormat(out);

    i++;
    frame_node++;

    if (frame_node != it_end)
      out->append(",");
  }

  out->append("}");  // End the |stackFrames| dictionary.
}

void StackFrameDeduplicator::EstimateTraceMemoryOverhead(
    TraceEventMemoryOverhead* overhead) {
  // The sizes here are only estimates; they fail to take into account the
  // overhead of the tree nodes for the map, but as an estimate this should be
  // fine.
  size_t maps_size = roots_.size() * sizeof(std::pair<StackFrame, int>);
  size_t frames_allocated = frames_.capacity() * sizeof(FrameNode);
  size_t frames_resident = frames_.size() * sizeof(FrameNode);

  for (const FrameNode& node : frames_)
    maps_size += node.children.size() * sizeof(std::pair<StackFrame, int>);

  overhead->Add("StackFrameDeduplicator",
                sizeof(StackFrameDeduplicator) + maps_size + frames_allocated,
                sizeof(StackFrameDeduplicator) + maps_size + frames_resident);
}

}  // namespace trace_event
}  // namespace base

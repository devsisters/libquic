// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/strike_register.h"

#include <algorithm>
#include <limits>

#include "base/logging.h"

using std::pair;
using std::set;
using std::vector;

namespace net {

namespace {

uint32_t GetInitialHorizon(uint32_t current_time_internal,
                           uint32_t window_secs,
                           StrikeRegister::StartupType startup) {
  if (startup == StrikeRegister::DENY_REQUESTS_AT_STARTUP) {
    // The horizon is initially set |window_secs| into the future because, if
    // we just crashed, then we may have accepted nonces in the span
    // [current_time...current_time+window_secs] and so we conservatively
    // reject the whole timespan unless |startup| tells us otherwise.
    return current_time_internal + window_secs + 1;
  } else {  // startup == StrikeRegister::NO_STARTUP_PERIOD_NEEDED
    // The orbit can be assumed to be globally unique.  Use a horizon
    // in the past.
    return 0;
  }
}

}  // namespace

// static
const uint32_t StrikeRegister::kExternalNodeSize = 24;
// static
const uint32_t StrikeRegister::kNil = (1u << 31) | 1;
// static
const uint32_t StrikeRegister::kExternalFlag = 1 << 23;

// InternalNode represents a non-leaf node in the critbit tree. See the comment
// in the .h file for details.
class StrikeRegister::InternalNode {
 public:
  void SetChild(unsigned direction, uint32_t child) {
    data_[direction] = (data_[direction] & 0xff) | (child << 8);
  }

  void SetCritByte(uint8_t critbyte) {
    data_[0] = (data_[0] & 0xffffff00) | critbyte;
  }

  void SetOtherBits(uint8_t otherbits) {
    data_[1] = (data_[1] & 0xffffff00) | otherbits;
  }

  void SetNextPtr(uint32_t next) { data_[0] = next; }

  uint32_t next() const { return data_[0]; }

  uint32_t child(unsigned n) const { return data_[n] >> 8; }

  uint8_t critbyte() const { return static_cast<uint8_t>(data_[0]); }

  uint8_t otherbits() const { return static_cast<uint8_t>(data_[1]); }

  // These bytes are organised thus:
  //   <24 bits> left child
  //   <8 bits> crit-byte
  //   <24 bits> right child
  //   <8 bits> other-bits
  uint32_t data_[2];
};

// kCreationTimeFromInternalEpoch contains the number of seconds between the
// start of the internal epoch and the creation time. This allows us
// to consider times that are before the creation time.
static const uint32_t kCreationTimeFromInternalEpoch = 63115200;  // 2 years.

void StrikeRegister::ValidateStrikeRegisterConfig(unsigned max_entries) {
  // We only have 23 bits of index available.
  CHECK_LT(max_entries, 1u << 23);
  CHECK_GT(max_entries, 1u);           // There must be at least two entries.
  CHECK_EQ(sizeof(InternalNode), 8u);  // in case of compiler changes.
}

StrikeRegister::StrikeRegister(unsigned max_entries,
                               uint32_t current_time,
                               uint32_t window_secs,
                               const uint8_t orbit[8],
                               StartupType startup)
    : max_entries_(max_entries),
      window_secs_(window_secs),
      internal_epoch_(current_time > kCreationTimeFromInternalEpoch
                          ? current_time - kCreationTimeFromInternalEpoch
                          : 0),
      horizon_(GetInitialHorizon(ExternalTimeToInternal(current_time),
                                 window_secs,
                                 startup)) {
  memcpy(orbit_, orbit, sizeof(orbit_));

  ValidateStrikeRegisterConfig(max_entries);
  internal_nodes_ = new InternalNode[max_entries];
  external_nodes_.reset(new uint8_t[kExternalNodeSize * max_entries]);

  Reset();
}

StrikeRegister::~StrikeRegister() {
  delete[] internal_nodes_;
}

void StrikeRegister::Reset() {
  // Thread a free list through all of the internal nodes.
  internal_node_free_head_ = 0;
  for (unsigned i = 0; i < max_entries_ - 1; i++) {
    internal_nodes_[i].SetNextPtr(i + 1);
  }
  internal_nodes_[max_entries_ - 1].SetNextPtr(kNil);

  // Also thread a free list through the external nodes.
  external_node_free_head_ = 0;
  for (unsigned i = 0; i < max_entries_ - 1; i++) {
    external_node_next_ptr(i) = i + 1;
  }
  external_node_next_ptr(max_entries_ - 1) = kNil;

  // This is the root of the tree.
  internal_node_head_ = kNil;
}

InsertStatus StrikeRegister::Insert(const uint8_t nonce[32],
                                    uint32_t current_time_external) {
  // Make space for the insertion if the strike register is full.
  while (external_node_free_head_ == kNil || internal_node_free_head_ == kNil) {
    DropOldestNode();
  }

  const uint32_t current_time = ExternalTimeToInternal(current_time_external);

  // Check to see if the orbit is correct.
  if (memcmp(nonce + sizeof(current_time), orbit_, sizeof(orbit_))) {
    return NONCE_INVALID_ORBIT_FAILURE;
  }

  const uint32_t nonce_time = ExternalTimeToInternal(TimeFromBytes(nonce));

  // Check that the timestamp is in the valid range.
  pair<uint32_t, uint32_t> valid_range =
      StrikeRegister::GetValidRange(current_time);
  if (nonce_time < valid_range.first || nonce_time > valid_range.second) {
    return NONCE_INVALID_TIME_FAILURE;
  }

  // We strip the orbit out of the nonce.
  uint8_t value[24];
  memcpy(value, nonce, sizeof(nonce_time));
  memcpy(value + sizeof(nonce_time),
         nonce + sizeof(nonce_time) + sizeof(orbit_),
         sizeof(value) - sizeof(nonce_time));

  // Find the best match to |value| in the crit-bit tree. The best match is
  // simply the value which /could/ match |value|, if any does, so we still
  // need a memcmp to check.
  uint32_t best_match_index = BestMatch(value);
  if (best_match_index == kNil) {
    // Empty tree. Just insert the new value at the root.
    uint32_t index = GetFreeExternalNode();
    memcpy(external_node(index), value, sizeof(value));
    internal_node_head_ = (index | kExternalFlag) << 8;
    DCHECK_LE(horizon_, nonce_time);
    return NONCE_OK;
  }

  const uint8_t* best_match = external_node(best_match_index);
  if (memcmp(best_match, value, sizeof(value)) == 0) {
    // We found the value in the tree.
    return NONCE_NOT_UNIQUE_FAILURE;
  }

  // We are going to insert a new entry into the tree, so get the nodes now.
  uint32_t internal_node_index = GetFreeInternalNode();
  uint32_t external_node_index = GetFreeExternalNode();

  // If we just evicted the best match, then we have to try and match again.
  // We know that we didn't just empty the tree because we require that
  // max_entries_ >= 2. Also, we know that it doesn't match because, if it
  // did, it would have been returned previously.
  if (external_node_index == best_match_index) {
    best_match_index = BestMatch(value);
    best_match = external_node(best_match_index);
  }

  // Now we need to find the first bit where we differ from |best_match|.
  uint8_t differing_byte;
  uint8_t new_other_bits;
  for (differing_byte = 0; differing_byte < arraysize(value);
       differing_byte++) {
    new_other_bits = value[differing_byte] ^ best_match[differing_byte];
    if (new_other_bits) {
      break;
    }
  }

  // Once we have the XOR the of first differing byte in new_other_bits we need
  // to find the most significant differing bit. We could do this with a simple
  // for loop, testing bits 7..0. Instead we fold the bits so that we end up
  // with a byte where all the bits below the most significant one, are set.
  new_other_bits |= new_other_bits >> 1;
  new_other_bits |= new_other_bits >> 2;
  new_other_bits |= new_other_bits >> 4;
  // Now this bit trick results in all the bits set, except the original
  // most-significant one.
  new_other_bits = (new_other_bits & ~(new_other_bits >> 1)) ^ 255;

  // Consider the effect of ORing against |new_other_bits|. If |value| did not
  // have the critical bit set, the result is the same as |new_other_bits|. If
  // it did, the result is all ones.

  unsigned newdirection;
  if ((new_other_bits | value[differing_byte]) == 0xff) {
    newdirection = 1;
  } else {
    newdirection = 0;
  }

  memcpy(external_node(external_node_index), value, sizeof(value));
  InternalNode* inode = &internal_nodes_[internal_node_index];

  inode->SetChild(newdirection, external_node_index | kExternalFlag);
  inode->SetCritByte(differing_byte);
  inode->SetOtherBits(new_other_bits);

  // |where_index| is a pointer to the uint32_t which needs to be updated in
  // order to insert the new internal node into the tree. The internal nodes
  // store the child indexes in the top 24-bits of a 32-bit word and, to keep
  // the code simple, we define that |internal_node_head_| is organised the
  // same way.
  DCHECK_EQ(internal_node_head_ & 0xff, 0u);
  uint32_t* where_index = &internal_node_head_;
  while (((*where_index >> 8) & kExternalFlag) == 0) {
    InternalNode* node = &internal_nodes_[*where_index >> 8];
    if (node->critbyte() > differing_byte) {
      break;
    }
    if (node->critbyte() == differing_byte &&
        node->otherbits() > new_other_bits) {
      break;
    }
    if (node->critbyte() == differing_byte &&
        node->otherbits() == new_other_bits) {
      CHECK(false);
    }

    uint8_t c = value[node->critbyte()];
    const int direction =
        (1 + static_cast<unsigned>(node->otherbits() | c)) >> 8;
    where_index = &node->data_[direction];
  }

  inode->SetChild(newdirection ^ 1, *where_index >> 8);
  *where_index = (*where_index & 0xff) | (internal_node_index << 8);

  DCHECK_LE(horizon_, nonce_time);
  return NONCE_OK;
}

const uint8_t* StrikeRegister::orbit() const {
  return orbit_;
}

uint32_t StrikeRegister::GetCurrentValidWindowSecs(
    uint32_t current_time_external) const {
  uint32_t current_time = ExternalTimeToInternal(current_time_external);
  pair<uint32_t, uint32_t> valid_range =
      StrikeRegister::GetValidRange(current_time);
  if (valid_range.second >= valid_range.first) {
    return valid_range.second - current_time + 1;
  } else {
    return 0;
  }
}

void StrikeRegister::Validate() {
  set<uint32_t> free_internal_nodes;
  for (uint32_t i = internal_node_free_head_; i != kNil;
       i = internal_nodes_[i].next()) {
    CHECK_LT(i, max_entries_);
    CHECK_EQ(free_internal_nodes.count(i), 0u);
    free_internal_nodes.insert(i);
  }

  set<uint32_t> free_external_nodes;
  for (uint32_t i = external_node_free_head_; i != kNil;
       i = external_node_next_ptr(i)) {
    CHECK_LT(i, max_entries_);
    CHECK_EQ(free_external_nodes.count(i), 0u);
    free_external_nodes.insert(i);
  }

  set<uint32_t> used_external_nodes;
  set<uint32_t> used_internal_nodes;

  if (internal_node_head_ != kNil &&
      ((internal_node_head_ >> 8) & kExternalFlag) == 0) {
    vector<pair<unsigned, bool>> bits;
    ValidateTree(internal_node_head_ >> 8, -1, bits, free_internal_nodes,
                 free_external_nodes, &used_internal_nodes,
                 &used_external_nodes);
  }
}

// static
uint32_t StrikeRegister::TimeFromBytes(const uint8_t d[4]) {
  return static_cast<uint32_t>(d[0]) << 24 | static_cast<uint32_t>(d[1]) << 16 |
         static_cast<uint32_t>(d[2]) << 8 | static_cast<uint32_t>(d[3]);
}

pair<uint32_t, uint32_t> StrikeRegister::GetValidRange(
    uint32_t current_time_internal) const {
  if (current_time_internal < horizon_) {
    // Empty valid range.
    return std::make_pair(std::numeric_limits<uint32_t>::max(), 0);
  }

  uint32_t lower_bound;
  if (current_time_internal >= window_secs_) {
    lower_bound = std::max(horizon_, current_time_internal - window_secs_);
  } else {
    lower_bound = horizon_;
  }

  // Also limit the upper range based on horizon_.  This makes the
  // strike register reject inserts that are far in the future and
  // would consume strike register resources for a long time.  This
  // allows the strike server to degrade optimally in cases where the
  // insert rate exceeds |max_entries_ / (2 * window_secs_)| entries
  // per second.
  uint32_t upper_bound =
      current_time_internal +
      std::min(current_time_internal - horizon_, window_secs_);

  return std::make_pair(lower_bound, upper_bound);
}

uint32_t StrikeRegister::ExternalTimeToInternal(uint32_t external_time) const {
  return external_time - internal_epoch_;
}

uint32_t StrikeRegister::BestMatch(const uint8_t v[24]) const {
  if (internal_node_head_ == kNil) {
    return kNil;
  }

  uint32_t next = internal_node_head_ >> 8;
  while ((next & kExternalFlag) == 0) {
    InternalNode* node = &internal_nodes_[next];
    uint8_t b = v[node->critbyte()];
    unsigned direction =
        (1 + static_cast<unsigned>(node->otherbits() | b)) >> 8;
    next = node->child(direction);
  }

  return next & ~kExternalFlag;
}

uint32_t& StrikeRegister::external_node_next_ptr(unsigned i) {
  return *reinterpret_cast<uint32_t*>(&external_nodes_[i * kExternalNodeSize]);
}

uint8_t* StrikeRegister::external_node(unsigned i) {
  return &external_nodes_[i * kExternalNodeSize];
}

uint32_t StrikeRegister::GetFreeExternalNode() {
  uint32_t index = external_node_free_head_;
  DCHECK(index != kNil);
  external_node_free_head_ = external_node_next_ptr(index);
  return index;
}

uint32_t StrikeRegister::GetFreeInternalNode() {
  uint32_t index = internal_node_free_head_;
  DCHECK(index != kNil);
  internal_node_free_head_ = internal_nodes_[index].next();
  return index;
}

void StrikeRegister::DropOldestNode() {
  // DropOldestNode should never be called on an empty tree.
  DCHECK(internal_node_head_ != kNil);

  // An internal node in a crit-bit tree always has exactly two children.
  // This means that, if we are removing an external node (which is one of
  // those children), then we also need to remove an internal node. In order
  // to do that we keep pointers to the parent (wherep) and grandparent
  // (whereq) when walking down the tree.

  uint32_t p = internal_node_head_ >> 8, *wherep = &internal_node_head_,
           *whereq = nullptr;
  while ((p & kExternalFlag) == 0) {
    whereq = wherep;
    InternalNode* inode = &internal_nodes_[p];
    // We always go left, towards the smallest element, exploiting the fact
    // that the timestamp is big-endian and at the start of the value.
    wherep = &inode->data_[0];
    p = (*wherep) >> 8;
  }

  const uint32_t ext_index = p & ~kExternalFlag;
  const uint8_t* ext_node = external_node(ext_index);
  uint32_t new_horizon = ExternalTimeToInternal(TimeFromBytes(ext_node)) + 1;
  DCHECK_LE(horizon_, new_horizon);
  horizon_ = new_horizon;

  if (!whereq) {
    // We are removing the last element in a tree.
    internal_node_head_ = kNil;
    FreeExternalNode(ext_index);
    return;
  }

  // |wherep| points to the left child pointer in the parent so we can add
  // one and dereference to get the right child.
  const uint32_t other_child = wherep[1];
  FreeInternalNode((*whereq) >> 8);
  *whereq = (*whereq & 0xff) | (other_child & 0xffffff00);
  FreeExternalNode(ext_index);
}

void StrikeRegister::FreeExternalNode(uint32_t index) {
  external_node_next_ptr(index) = external_node_free_head_;
  external_node_free_head_ = index;
}

void StrikeRegister::FreeInternalNode(uint32_t index) {
  internal_nodes_[index].SetNextPtr(internal_node_free_head_);
  internal_node_free_head_ = index;
}

void StrikeRegister::ValidateTree(uint32_t internal_node,
                                  int last_bit,
                                  const vector<pair<unsigned, bool>>& bits,
                                  const set<uint32_t>& free_internal_nodes,
                                  const set<uint32_t>& free_external_nodes,
                                  set<uint32_t>* used_internal_nodes,
                                  set<uint32_t>* used_external_nodes) {
  CHECK_LT(internal_node, max_entries_);
  const InternalNode* i = &internal_nodes_[internal_node];
  unsigned bit = 0;
  switch (i->otherbits()) {
    case 0xff & ~(1 << 7):
      bit = 0;
      break;
    case 0xff & ~(1 << 6):
      bit = 1;
      break;
    case 0xff & ~(1 << 5):
      bit = 2;
      break;
    case 0xff & ~(1 << 4):
      bit = 3;
      break;
    case 0xff & ~(1 << 3):
      bit = 4;
      break;
    case 0xff & ~(1 << 2):
      bit = 5;
      break;
    case 0xff & ~(1 << 1):
      bit = 6;
      break;
    case 0xff & ~1:
      bit = 7;
      break;
    default:
      CHECK(false);
  }

  bit += 8 * i->critbyte();
  if (last_bit > -1) {
    CHECK_GT(bit, static_cast<unsigned>(last_bit));
  }

  CHECK_EQ(free_internal_nodes.count(internal_node), 0u);

  for (unsigned child = 0; child < 2; child++) {
    if (i->child(child) & kExternalFlag) {
      uint32_t ext = i->child(child) & ~kExternalFlag;
      CHECK_EQ(free_external_nodes.count(ext), 0u);
      CHECK_EQ(used_external_nodes->count(ext), 0u);
      used_external_nodes->insert(ext);
      const uint8_t* bytes = external_node(ext);
      for (const pair<unsigned, bool>& pair : bits) {
        unsigned byte = pair.first / 8;
        DCHECK_LE(byte, 0xffu);
        unsigned bit_new = pair.first % 8;
        static const uint8_t kMasks[8] = {0x80, 0x40, 0x20, 0x10,
                                          0x08, 0x04, 0x02, 0x01};
        CHECK_EQ((bytes[byte] & kMasks[bit_new]) != 0, pair.second);
      }
    } else {
      uint32_t inter = i->child(child);
      vector<pair<unsigned, bool>> new_bits(bits);
      new_bits.push_back(pair<unsigned, bool>(bit, child != 0));
      CHECK_EQ(free_internal_nodes.count(inter), 0u);
      CHECK_EQ(used_internal_nodes->count(inter), 0u);
      used_internal_nodes->insert(inter);
      ValidateTree(inter, bit, bits, free_internal_nodes, free_external_nodes,
                   used_internal_nodes, used_external_nodes);
    }
  }
}

}  // namespace net

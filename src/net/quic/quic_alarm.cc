// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_alarm.h"

#include "base/logging.h"
#include "net/quic/quic_flags.h"

namespace net {

QuicAlarm::QuicAlarm(QuicArenaScopedPtr<Delegate> delegate)
    : delegate_(std::move(delegate)), deadline_(QuicTime::Zero()) {}

QuicAlarm::~QuicAlarm() {}

void QuicAlarm::Set(QuicTime new_deadline) {
  DCHECK(!IsSet());
  DCHECK(new_deadline.IsInitialized());
  deadline_ = new_deadline;
  SetImpl();
}

void QuicAlarm::Cancel() {
  if (!IsSet()) {
    // Don't try to cancel an alarm that hasn't been set.
    return;
  }
  deadline_ = QuicTime::Zero();
  CancelImpl();
}

void QuicAlarm::Update(QuicTime new_deadline, QuicTime::Delta granularity) {
  if (!new_deadline.IsInitialized()) {
    Cancel();
    return;
  }
  if (std::abs(new_deadline.Subtract(deadline_).ToMicroseconds()) <
      granularity.ToMicroseconds()) {
    return;
  }
  Cancel();
  Set(new_deadline);
}

bool QuicAlarm::IsSet() const {
  return deadline_.IsInitialized();
}

void QuicAlarm::Fire() {
  if (!IsSet()) {
    return;
  }

  deadline_ = QuicTime::Zero();
  delegate_->OnAlarm();
}

}  // namespace net

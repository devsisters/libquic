// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_alarm.h"

#include "base/logging.h"

namespace net {

QuicAlarm::QuicAlarm(QuicArenaScopedPtr<Delegate> delegate)
    : delegate_(std::move(delegate)), deadline_(QuicTime::Zero()) {}

QuicAlarm::~QuicAlarm() {}

void QuicAlarm::Set(QuicTime deadline) {
  DCHECK(!IsSet());
  DCHECK(deadline.IsInitialized());
  deadline_ = deadline;
  SetImpl();
}

void QuicAlarm::Cancel() {
  deadline_ = QuicTime::Zero();
  CancelImpl();
}

void QuicAlarm::Update(QuicTime deadline, QuicTime::Delta granularity) {
  if (!deadline.IsInitialized()) {
    Cancel();
    return;
  }
  if (std::abs(deadline.Subtract(deadline_).ToMicroseconds()) <
      granularity.ToMicroseconds()) {
    return;
  }
  Cancel();
  Set(deadline);
}

bool QuicAlarm::IsSet() const {
  return deadline_.IsInitialized();
}

void QuicAlarm::Fire() {
  if (!deadline_.IsInitialized()) {
    return;
  }

  deadline_ = QuicTime::Zero();
  QuicTime deadline = delegate_->OnAlarm();
  // delegate_->OnAlarm() might call Set(), in which case deadline_
  // will already contain the new value, so don't overwrite it.  Also,
  // OnAlarm() might delete |this| so check |deadline| before
  // |deadline_|.
  if (deadline.IsInitialized() && !deadline_.IsInitialized()) {
    Set(deadline);
  }
}

}  // namespace net

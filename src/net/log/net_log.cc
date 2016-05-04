// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/net_log.h"

#include <utility>

#include "base/bind.h"
#include "base/debug/alias.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/net_errors.h"

namespace net {

namespace {

// Returns parameters for logging data transferred events. At a minimum includes
// the number of bytes transferred. If the capture mode allows logging byte
// contents and |byte_count| > 0, then will include the actual bytes. The
// bytes are hex-encoded, since base::StringValue only supports UTF-8.
std::unique_ptr<base::Value> BytesTransferredCallback(
    int byte_count,
    const char* bytes,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("byte_count", byte_count);
  if (capture_mode.include_socket_bytes() && byte_count > 0)
    dict->SetString("hex_encoded_bytes", base::HexEncode(bytes, byte_count));
  return std::move(dict);
}

std::unique_ptr<base::Value> SourceEventParametersCallback(
    const NetLog::Source source,
    NetLogCaptureMode /* capture_mode */) {
  if (!source.IsValid())
    return std::unique_ptr<base::Value>();
  std::unique_ptr<base::DictionaryValue> event_params(
      new base::DictionaryValue());
  source.AddToEventParameters(event_params.get());
  return std::move(event_params);
}

std::unique_ptr<base::Value> NetLogBoolCallback(
    const char* name,
    bool value,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> event_params(
      new base::DictionaryValue());
  event_params->SetBoolean(name, value);
  return std::move(event_params);
}

std::unique_ptr<base::Value> NetLogIntCallback(
    const char* name,
    int value,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> event_params(
      new base::DictionaryValue());
  event_params->SetInteger(name, value);
  return std::move(event_params);
}

std::unique_ptr<base::Value> NetLogInt64Callback(
    const char* name,
    int64_t value,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> event_params(
      new base::DictionaryValue());
  event_params->SetString(name, base::Int64ToString(value));
  return std::move(event_params);
}

std::unique_ptr<base::Value> NetLogStringCallback(
    const char* name,
    const std::string* value,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> event_params(
      new base::DictionaryValue());
  event_params->SetString(name, *value);
  return std::move(event_params);
}

std::unique_ptr<base::Value> NetLogString16Callback(
    const char* name,
    const base::string16* value,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> event_params(
      new base::DictionaryValue());
  event_params->SetString(name, *value);
  return std::move(event_params);
}

}  // namespace

// LoadTimingInfo requires this be 0.
const uint32_t NetLog::Source::kInvalidId = 0;

NetLog::Source::Source() : type(SOURCE_NONE), id(kInvalidId) {
}

NetLog::Source::Source(SourceType type, uint32_t id) : type(type), id(id) {}

bool NetLog::Source::IsValid() const {
  return id != kInvalidId;
}

void NetLog::Source::AddToEventParameters(
    base::DictionaryValue* event_params) const {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("type", static_cast<int>(type));
  dict->SetInteger("id", static_cast<int>(id));
  event_params->Set("source_dependency", std::move(dict));
}

NetLog::ParametersCallback NetLog::Source::ToEventParametersCallback() const {
  return base::Bind(&SourceEventParametersCallback, *this);
}

// static
bool NetLog::Source::FromEventParameters(base::Value* event_params,
                                         Source* source) {
  base::DictionaryValue* dict = NULL;
  base::DictionaryValue* source_dict = NULL;
  int source_id = -1;
  int source_type = NetLog::SOURCE_COUNT;
  if (!event_params || !event_params->GetAsDictionary(&dict) ||
      !dict->GetDictionary("source_dependency", &source_dict) ||
      !source_dict->GetInteger("id", &source_id) ||
      !source_dict->GetInteger("type", &source_type)) {
    *source = Source();
    return false;
  }

  DCHECK_GE(source_id, 0);
  DCHECK_LT(source_type, NetLog::SOURCE_COUNT);
  *source = Source(static_cast<SourceType>(source_type), source_id);
  return true;
}

base::Value* NetLog::Entry::ToValue() const {
  std::unique_ptr<base::DictionaryValue> entry_dict(
      new base::DictionaryValue());

  entry_dict->SetString("time", TickCountToString(data_->time));

  // Set the entry source.
  std::unique_ptr<base::DictionaryValue> source_dict(
      new base::DictionaryValue());
  source_dict->SetInteger("id", data_->source.id);
  source_dict->SetInteger("type", static_cast<int>(data_->source.type));
  entry_dict->Set("source", std::move(source_dict));

  // Set the event info.
  entry_dict->SetInteger("type", static_cast<int>(data_->type));
  entry_dict->SetInteger("phase", static_cast<int>(data_->phase));

  // Set the event-specific parameters.
  if (data_->parameters_callback) {
    std::unique_ptr<base::Value> value(
        data_->parameters_callback->Run(capture_mode_));
    if (value)
      entry_dict->Set("params", std::move(value));
  }

  return entry_dict.release();
}

std::unique_ptr<base::Value> NetLog::Entry::ParametersToValue() const {
  if (data_->parameters_callback)
    return data_->parameters_callback->Run(capture_mode_);
  return nullptr;
}

NetLog::EntryData::EntryData(EventType type,
                             Source source,
                             EventPhase phase,
                             base::TimeTicks time,
                             const ParametersCallback* parameters_callback)
    : type(type),
      source(source),
      phase(phase),
      time(time),
      parameters_callback(parameters_callback) {
}

NetLog::EntryData::~EntryData() {
}

NetLog::Entry::Entry(const EntryData* data, NetLogCaptureMode capture_mode)
    : data_(data), capture_mode_(capture_mode) {
}

NetLog::Entry::~Entry() {
}

NetLog::ThreadSafeObserver::ThreadSafeObserver() : net_log_(NULL) {
}

NetLog::ThreadSafeObserver::~ThreadSafeObserver() {
  // Make sure we aren't watching a NetLog on destruction.  Because the NetLog
  // may pass events to each observer on multiple threads, we cannot safely
  // stop watching a NetLog automatically from a parent class.
  DCHECK(!net_log_);
}

NetLogCaptureMode NetLog::ThreadSafeObserver::capture_mode() const {
  DCHECK(net_log_);
  return capture_mode_;
}

NetLog* NetLog::ThreadSafeObserver::net_log() const {
  return net_log_;
}

void NetLog::ThreadSafeObserver::OnAddEntryData(const EntryData& entry_data) {
  OnAddEntry(Entry(&entry_data, capture_mode()));
}

NetLog::NetLog() : last_id_(0), is_capturing_(0) {
}

NetLog::~NetLog() {
}

void NetLog::AddGlobalEntry(EventType type) {
  AddEntry(type, Source(NetLog::SOURCE_NONE, NextID()), NetLog::PHASE_NONE,
           NULL);
}

void NetLog::AddGlobalEntry(
    EventType type,
    const NetLog::ParametersCallback& parameters_callback) {
  AddEntry(type, Source(NetLog::SOURCE_NONE, NextID()), NetLog::PHASE_NONE,
           &parameters_callback);
}

uint32_t NetLog::NextID() {
  return base::subtle::NoBarrier_AtomicIncrement(&last_id_, 1);
}

bool NetLog::IsCapturing() const {
  return base::subtle::NoBarrier_Load(&is_capturing_) != 0;
}

void NetLog::DeprecatedAddObserver(NetLog::ThreadSafeObserver* observer,
                                   NetLogCaptureMode capture_mode) {
  base::AutoLock lock(lock_);

  DCHECK(!observer->net_log_);
  observers_.AddObserver(observer);
  observer->net_log_ = this;
  observer->capture_mode_ = capture_mode;
  UpdateIsCapturing();
}

void NetLog::SetObserverCaptureMode(NetLog::ThreadSafeObserver* observer,
                                    NetLogCaptureMode capture_mode) {
  base::AutoLock lock(lock_);

  DCHECK(observers_.HasObserver(observer));
  DCHECK_EQ(this, observer->net_log_);
  observer->capture_mode_ = capture_mode;
}

void NetLog::DeprecatedRemoveObserver(NetLog::ThreadSafeObserver* observer) {
  base::AutoLock lock(lock_);

  DCHECK(observers_.HasObserver(observer));
  DCHECK_EQ(this, observer->net_log_);
  observers_.RemoveObserver(observer);
  observer->net_log_ = NULL;
  observer->capture_mode_ = NetLogCaptureMode();
  UpdateIsCapturing();
}

void NetLog::UpdateIsCapturing() {
  lock_.AssertAcquired();
  base::subtle::NoBarrier_Store(&is_capturing_,
                                observers_.might_have_observers() ? 1 : 0);
}

// static
std::string NetLog::TickCountToString(const base::TimeTicks& time) {
  int64_t delta_time = (time - base::TimeTicks()).InMilliseconds();
  return base::Int64ToString(delta_time);
}

// static
const char* NetLog::EventTypeToString(EventType event) {
  switch (event) {
#define EVENT_TYPE(label) \
  case TYPE_##label:      \
    return #label;
#include "net/log/net_log_event_type_list.h"
#undef EVENT_TYPE
    default:
      NOTREACHED();
      return NULL;
  }
}

// static
base::Value* NetLog::GetEventTypesAsValue() {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  for (int i = 0; i < EVENT_COUNT; ++i) {
    dict->SetInteger(EventTypeToString(static_cast<EventType>(i)), i);
  }
  return dict.release();
}

// static
const char* NetLog::SourceTypeToString(SourceType source) {
  switch (source) {
#define SOURCE_TYPE(label) \
  case SOURCE_##label:     \
    return #label;
#include "net/log/net_log_source_type_list.h"
#undef SOURCE_TYPE
    default:
      NOTREACHED();
      return NULL;
  }
}

// static
base::Value* NetLog::GetSourceTypesAsValue() {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  for (int i = 0; i < SOURCE_COUNT; ++i) {
    dict->SetInteger(SourceTypeToString(static_cast<SourceType>(i)), i);
  }
  return dict.release();
}

// static
const char* NetLog::EventPhaseToString(EventPhase phase) {
  switch (phase) {
    case PHASE_BEGIN:
      return "PHASE_BEGIN";
    case PHASE_END:
      return "PHASE_END";
    case PHASE_NONE:
      return "PHASE_NONE";
  }
  NOTREACHED();
  return NULL;
}

// static
NetLog::ParametersCallback NetLog::BoolCallback(const char* name, bool value) {
  return base::Bind(&NetLogBoolCallback, name, value);
}

// static
NetLog::ParametersCallback NetLog::IntCallback(const char* name, int value) {
  return base::Bind(&NetLogIntCallback, name, value);
}

// static
NetLog::ParametersCallback NetLog::Int64Callback(const char* name,
                                                 int64_t value) {
  return base::Bind(&NetLogInt64Callback, name, value);
}

// static
NetLog::ParametersCallback NetLog::StringCallback(const char* name,
                                                  const std::string* value) {
  DCHECK(value);
  return base::Bind(&NetLogStringCallback, name, value);
}

// static
NetLog::ParametersCallback NetLog::StringCallback(const char* name,
                                                  const base::string16* value) {
  DCHECK(value);
  return base::Bind(&NetLogString16Callback, name, value);
}

void NetLog::AddEntry(EventType type,
                      const Source& source,
                      EventPhase phase,
                      const NetLog::ParametersCallback* parameters_callback) {
  if (!IsCapturing())
    return;
  EntryData entry_data(type, source, phase, base::TimeTicks::Now(),
                       parameters_callback);

  // Notify all of the log observers.
  base::AutoLock lock(lock_);
  FOR_EACH_OBSERVER(ThreadSafeObserver, observers_, OnAddEntryData(entry_data));
}

BoundNetLog::~BoundNetLog() {
  liveness_ = DEAD;
}

void BoundNetLog::AddEntry(NetLog::EventType type,
                           NetLog::EventPhase phase) const {
  CrashIfInvalid();

  if (!net_log_)
    return;
  net_log_->AddEntry(type, source_, phase, NULL);
}

void BoundNetLog::AddEntry(
    NetLog::EventType type,
    NetLog::EventPhase phase,
    const NetLog::ParametersCallback& get_parameters) const {
  CrashIfInvalid();

  if (!net_log_)
    return;
  net_log_->AddEntry(type, source_, phase, &get_parameters);
}

void BoundNetLog::AddEvent(NetLog::EventType type) const {
  AddEntry(type, NetLog::PHASE_NONE);
}

void BoundNetLog::AddEvent(
    NetLog::EventType type,
    const NetLog::ParametersCallback& get_parameters) const {
  AddEntry(type, NetLog::PHASE_NONE, get_parameters);
}

void BoundNetLog::BeginEvent(NetLog::EventType type) const {
  AddEntry(type, NetLog::PHASE_BEGIN);
}

void BoundNetLog::BeginEvent(
    NetLog::EventType type,
    const NetLog::ParametersCallback& get_parameters) const {
  AddEntry(type, NetLog::PHASE_BEGIN, get_parameters);
}

void BoundNetLog::EndEvent(NetLog::EventType type) const {
  AddEntry(type, NetLog::PHASE_END);
}

void BoundNetLog::EndEvent(
    NetLog::EventType type,
    const NetLog::ParametersCallback& get_parameters) const {
  AddEntry(type, NetLog::PHASE_END, get_parameters);
}

void BoundNetLog::AddEventWithNetErrorCode(NetLog::EventType event_type,
                                           int net_error) const {
  DCHECK_NE(ERR_IO_PENDING, net_error);
  if (net_error >= 0) {
    AddEvent(event_type);
  } else {
    AddEvent(event_type, NetLog::IntCallback("net_error", net_error));
  }
}

void BoundNetLog::EndEventWithNetErrorCode(NetLog::EventType event_type,
                                           int net_error) const {
  DCHECK_NE(ERR_IO_PENDING, net_error);
  if (net_error >= 0) {
    EndEvent(event_type);
  } else {
    EndEvent(event_type, NetLog::IntCallback("net_error", net_error));
  }
}

void BoundNetLog::AddByteTransferEvent(NetLog::EventType event_type,
                                       int byte_count,
                                       const char* bytes) const {
  AddEvent(event_type, base::Bind(BytesTransferredCallback, byte_count, bytes));
}

bool BoundNetLog::IsCapturing() const {
  CrashIfInvalid();
  return net_log_ && net_log_->IsCapturing();
}

// static
BoundNetLog BoundNetLog::Make(NetLog* net_log, NetLog::SourceType source_type) {
  if (!net_log)
    return BoundNetLog();

  NetLog::Source source(source_type, net_log->NextID());
  return BoundNetLog(source, net_log);
}

void BoundNetLog::CrashIfInvalid() const {
  Liveness liveness = liveness_;

  if (liveness == ALIVE)
    return;

  base::debug::Alias(&liveness);
  CHECK_EQ(ALIVE, liveness);
}

}  // namespace net

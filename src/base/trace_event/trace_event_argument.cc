// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/trace_event_argument.h"

#include <stdint.h>

#include <utility>

#include "base/bits.h"
#include "base/json/json_writer.h"
#include "base/memory/ptr_util.h"
#include "base/trace_event/trace_event_memory_overhead.h"
#include "base/values.h"

namespace base {
namespace trace_event {

namespace {
const char kTypeStartDict = '{';
const char kTypeEndDict = '}';
const char kTypeStartArray = '[';
const char kTypeEndArray = ']';
const char kTypeBool = 'b';
const char kTypeInt = 'i';
const char kTypeDouble = 'd';
const char kTypeString = 's';
const char kTypeCStr = '*';

#ifndef NDEBUG
const bool kStackTypeDict = false;
const bool kStackTypeArray = true;
#define DCHECK_CURRENT_CONTAINER_IS(x) DCHECK_EQ(x, nesting_stack_.back())
#define DCHECK_CONTAINER_STACK_DEPTH_EQ(x) DCHECK_EQ(x, nesting_stack_.size())
#define DEBUG_PUSH_CONTAINER(x) nesting_stack_.push_back(x)
#define DEBUG_POP_CONTAINER() nesting_stack_.pop_back()
#else
#define DCHECK_CURRENT_CONTAINER_IS(x) do {} while (0)
#define DCHECK_CONTAINER_STACK_DEPTH_EQ(x) do {} while (0)
#define DEBUG_PUSH_CONTAINER(x) do {} while (0)
#define DEBUG_POP_CONTAINER() do {} while (0)
#endif

inline void WriteKeyNameAsRawPtr(Pickle& pickle, const char* ptr) {
  pickle.WriteBytes(&kTypeCStr, 1);
  pickle.WriteUInt64(static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ptr)));
}

inline void WriteKeyNameWithCopy(Pickle& pickle, base::StringPiece str) {
  pickle.WriteBytes(&kTypeString, 1);
  pickle.WriteString(str);
}

std::string ReadKeyName(PickleIterator& pickle_iterator) {
  const char* type = nullptr;
  bool res = pickle_iterator.ReadBytes(&type, 1);
  std::string key_name;
  if (res && *type == kTypeCStr) {
    uint64_t ptr_value = 0;
    res = pickle_iterator.ReadUInt64(&ptr_value);
    key_name = reinterpret_cast<const char*>(static_cast<uintptr_t>(ptr_value));
  } else if (res && *type == kTypeString) {
    res = pickle_iterator.ReadString(&key_name);
  }
  DCHECK(res);
  return key_name;
}
}  // namespace

TracedValue::TracedValue() : TracedValue(0) {
}

TracedValue::TracedValue(size_t capacity) {
  DEBUG_PUSH_CONTAINER(kStackTypeDict);
  if (capacity)
    pickle_.Reserve(capacity);
}

TracedValue::~TracedValue() {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  DEBUG_POP_CONTAINER();
  DCHECK_CONTAINER_STACK_DEPTH_EQ(0u);
}

void TracedValue::SetInteger(const char* name, int value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  pickle_.WriteBytes(&kTypeInt, 1);
  pickle_.WriteInt(value);
  WriteKeyNameAsRawPtr(pickle_, name);
}

void TracedValue::SetIntegerWithCopiedName(base::StringPiece name, int value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  pickle_.WriteBytes(&kTypeInt, 1);
  pickle_.WriteInt(value);
  WriteKeyNameWithCopy(pickle_, name);
}

void TracedValue::SetDouble(const char* name, double value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  pickle_.WriteBytes(&kTypeDouble, 1);
  pickle_.WriteDouble(value);
  WriteKeyNameAsRawPtr(pickle_, name);
}

void TracedValue::SetDoubleWithCopiedName(base::StringPiece name,
                                          double value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  pickle_.WriteBytes(&kTypeDouble, 1);
  pickle_.WriteDouble(value);
  WriteKeyNameWithCopy(pickle_, name);
}

void TracedValue::SetBoolean(const char* name, bool value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  pickle_.WriteBytes(&kTypeBool, 1);
  pickle_.WriteBool(value);
  WriteKeyNameAsRawPtr(pickle_, name);
}

void TracedValue::SetBooleanWithCopiedName(base::StringPiece name,
                                           bool value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  pickle_.WriteBytes(&kTypeBool, 1);
  pickle_.WriteBool(value);
  WriteKeyNameWithCopy(pickle_, name);
}

void TracedValue::SetString(const char* name, base::StringPiece value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  pickle_.WriteBytes(&kTypeString, 1);
  pickle_.WriteString(value);
  WriteKeyNameAsRawPtr(pickle_, name);
}

void TracedValue::SetStringWithCopiedName(base::StringPiece name,
                                          base::StringPiece value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  pickle_.WriteBytes(&kTypeString, 1);
  pickle_.WriteString(value);
  WriteKeyNameWithCopy(pickle_, name);
}

void TracedValue::SetValue(const char* name, const TracedValue& value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  BeginDictionary(name);
  pickle_.WriteBytes(value.pickle_.payload(),
                     static_cast<int>(value.pickle_.payload_size()));
  EndDictionary();
}

void TracedValue::SetValueWithCopiedName(base::StringPiece name,
                                         const TracedValue& value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  BeginDictionaryWithCopiedName(name);
  pickle_.WriteBytes(value.pickle_.payload(),
                     static_cast<int>(value.pickle_.payload_size()));
  EndDictionary();
}

void TracedValue::BeginDictionary(const char* name) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  DEBUG_PUSH_CONTAINER(kStackTypeDict);
  pickle_.WriteBytes(&kTypeStartDict, 1);
  WriteKeyNameAsRawPtr(pickle_, name);
}

void TracedValue::BeginDictionaryWithCopiedName(base::StringPiece name) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  DEBUG_PUSH_CONTAINER(kStackTypeDict);
  pickle_.WriteBytes(&kTypeStartDict, 1);
  WriteKeyNameWithCopy(pickle_, name);
}

void TracedValue::BeginArray(const char* name) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  DEBUG_PUSH_CONTAINER(kStackTypeArray);
  pickle_.WriteBytes(&kTypeStartArray, 1);
  WriteKeyNameAsRawPtr(pickle_, name);
}

void TracedValue::BeginArrayWithCopiedName(base::StringPiece name) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  DEBUG_PUSH_CONTAINER(kStackTypeArray);
  pickle_.WriteBytes(&kTypeStartArray, 1);
  WriteKeyNameWithCopy(pickle_, name);
}

void TracedValue::EndDictionary() {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  DEBUG_POP_CONTAINER();
  pickle_.WriteBytes(&kTypeEndDict, 1);
}

void TracedValue::AppendInteger(int value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeArray);
  pickle_.WriteBytes(&kTypeInt, 1);
  pickle_.WriteInt(value);
}

void TracedValue::AppendDouble(double value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeArray);
  pickle_.WriteBytes(&kTypeDouble, 1);
  pickle_.WriteDouble(value);
}

void TracedValue::AppendBoolean(bool value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeArray);
  pickle_.WriteBytes(&kTypeBool, 1);
  pickle_.WriteBool(value);
}

void TracedValue::AppendString(base::StringPiece value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeArray);
  pickle_.WriteBytes(&kTypeString, 1);
  pickle_.WriteString(value);
}

void TracedValue::BeginArray() {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeArray);
  DEBUG_PUSH_CONTAINER(kStackTypeArray);
  pickle_.WriteBytes(&kTypeStartArray, 1);
}

void TracedValue::BeginDictionary() {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeArray);
  DEBUG_PUSH_CONTAINER(kStackTypeDict);
  pickle_.WriteBytes(&kTypeStartDict, 1);
}

void TracedValue::EndArray() {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeArray);
  DEBUG_POP_CONTAINER();
  pickle_.WriteBytes(&kTypeEndArray, 1);
}

void TracedValue::SetValue(const char* name,
                           std::unique_ptr<base::Value> value) {
  SetBaseValueWithCopiedName(name, *value);
}

void TracedValue::SetBaseValueWithCopiedName(base::StringPiece name,
                                             const base::Value& value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  switch (value.GetType()) {
    case base::Value::TYPE_NULL:
    case base::Value::TYPE_BINARY:
      NOTREACHED();
      break;

    case base::Value::TYPE_BOOLEAN: {
      bool bool_value;
      value.GetAsBoolean(&bool_value);
      SetBooleanWithCopiedName(name, bool_value);
    } break;

    case base::Value::TYPE_INTEGER: {
      int int_value;
      value.GetAsInteger(&int_value);
      SetIntegerWithCopiedName(name, int_value);
    } break;

    case base::Value::TYPE_DOUBLE: {
      double double_value;
      value.GetAsDouble(&double_value);
      SetDoubleWithCopiedName(name, double_value);
    } break;

    case base::Value::TYPE_STRING: {
      const StringValue* string_value;
      value.GetAsString(&string_value);
      SetStringWithCopiedName(name, string_value->GetString());
    } break;

    case base::Value::TYPE_DICTIONARY: {
      const DictionaryValue* dict_value;
      value.GetAsDictionary(&dict_value);
      BeginDictionaryWithCopiedName(name);
      for (DictionaryValue::Iterator it(*dict_value); !it.IsAtEnd();
           it.Advance()) {
        SetBaseValueWithCopiedName(it.key(), it.value());
      }
      EndDictionary();
    } break;

    case base::Value::TYPE_LIST: {
      const ListValue* list_value;
      value.GetAsList(&list_value);
      BeginArrayWithCopiedName(name);
      for (const auto& base_value : *list_value)
        AppendBaseValue(*base_value);
      EndArray();
    } break;
  }
}

void TracedValue::AppendBaseValue(const base::Value& value) {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeArray);
  switch (value.GetType()) {
    case base::Value::TYPE_NULL:
    case base::Value::TYPE_BINARY:
      NOTREACHED();
      break;

    case base::Value::TYPE_BOOLEAN: {
      bool bool_value;
      value.GetAsBoolean(&bool_value);
      AppendBoolean(bool_value);
    } break;

    case base::Value::TYPE_INTEGER: {
      int int_value;
      value.GetAsInteger(&int_value);
      AppendInteger(int_value);
    } break;

    case base::Value::TYPE_DOUBLE: {
      double double_value;
      value.GetAsDouble(&double_value);
      AppendDouble(double_value);
    } break;

    case base::Value::TYPE_STRING: {
      const StringValue* string_value;
      value.GetAsString(&string_value);
      AppendString(string_value->GetString());
    } break;

    case base::Value::TYPE_DICTIONARY: {
      const DictionaryValue* dict_value;
      value.GetAsDictionary(&dict_value);
      BeginDictionary();
      for (DictionaryValue::Iterator it(*dict_value); !it.IsAtEnd();
           it.Advance()) {
        SetBaseValueWithCopiedName(it.key(), it.value());
      }
      EndDictionary();
    } break;

    case base::Value::TYPE_LIST: {
      const ListValue* list_value;
      value.GetAsList(&list_value);
      BeginArray();
      for (const auto& base_value : *list_value)
        AppendBaseValue(*base_value);
      EndArray();
    } break;
  }
}

std::unique_ptr<base::Value> TracedValue::ToBaseValue() const {
  std::unique_ptr<DictionaryValue> root(new DictionaryValue);
  DictionaryValue* cur_dict = root.get();
  ListValue* cur_list = nullptr;
  std::vector<Value*> stack;
  PickleIterator it(pickle_);
  const char* type;

  while (it.ReadBytes(&type, 1)) {
    DCHECK((cur_dict && !cur_list) || (cur_list && !cur_dict));
    switch (*type) {
      case kTypeStartDict: {
        auto* new_dict = new DictionaryValue();
        if (cur_dict) {
          cur_dict->SetWithoutPathExpansion(ReadKeyName(it),
                                            WrapUnique(new_dict));
          stack.push_back(cur_dict);
          cur_dict = new_dict;
        } else {
          cur_list->Append(WrapUnique(new_dict));
          stack.push_back(cur_list);
          cur_list = nullptr;
          cur_dict = new_dict;
        }
      } break;

      case kTypeEndArray:
      case kTypeEndDict: {
        if (stack.back()->GetAsDictionary(&cur_dict)) {
          cur_list = nullptr;
        } else if (stack.back()->GetAsList(&cur_list)) {
          cur_dict = nullptr;
        }
        stack.pop_back();
      } break;

      case kTypeStartArray: {
        auto* new_list = new ListValue();
        if (cur_dict) {
          cur_dict->SetWithoutPathExpansion(ReadKeyName(it),
                                            WrapUnique(new_list));
          stack.push_back(cur_dict);
          cur_dict = nullptr;
          cur_list = new_list;
        } else {
          cur_list->Append(WrapUnique(new_list));
          stack.push_back(cur_list);
          cur_list = new_list;
        }
      } break;

      case kTypeBool: {
        bool value;
        CHECK(it.ReadBool(&value));
        if (cur_dict) {
          cur_dict->SetBooleanWithoutPathExpansion(ReadKeyName(it), value);
        } else {
          cur_list->AppendBoolean(value);
        }
      } break;

      case kTypeInt: {
        int value;
        CHECK(it.ReadInt(&value));
        if (cur_dict) {
          cur_dict->SetIntegerWithoutPathExpansion(ReadKeyName(it), value);
        } else {
          cur_list->AppendInteger(value);
        }
      } break;

      case kTypeDouble: {
        double value;
        CHECK(it.ReadDouble(&value));
        if (cur_dict) {
          cur_dict->SetDoubleWithoutPathExpansion(ReadKeyName(it), value);
        } else {
          cur_list->AppendDouble(value);
        }
      } break;

      case kTypeString: {
        std::string value;
        CHECK(it.ReadString(&value));
        if (cur_dict) {
          cur_dict->SetStringWithoutPathExpansion(ReadKeyName(it), value);
        } else {
          cur_list->AppendString(value);
        }
      } break;

      default:
        NOTREACHED();
    }
  }
  DCHECK(stack.empty());
  return std::move(root);
}

void TracedValue::AppendAsTraceFormat(std::string* out) const {
  DCHECK_CURRENT_CONTAINER_IS(kStackTypeDict);
  DCHECK_CONTAINER_STACK_DEPTH_EQ(1u);

  // TODO(primiano): this could be smarter, skip the ToBaseValue encoding and
  // produce the JSON on its own. This will require refactoring JSONWriter
  // to decouple the base::Value traversal from the JSON writing bits
  std::string tmp;
  JSONWriter::Write(*ToBaseValue(), &tmp);
  *out += tmp;
}

void TracedValue::EstimateTraceMemoryOverhead(
    TraceEventMemoryOverhead* overhead) {
  overhead->Add("TracedValue",
                /* allocated size */
                pickle_.GetTotalAllocatedSize(),
                /* resident size */
                pickle_.size());
}

}  // namespace trace_event
}  // namespace base

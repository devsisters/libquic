// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/trace_config.h"

#include <stddef.h>

#include <utility>

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/memory/ptr_util.h"
#include "base/strings/pattern.h"
#include "base/strings/string_split.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/memory_dump_request_args.h"
#include "base/trace_event/trace_event.h"

namespace base {
namespace trace_event {

namespace {

// String options that can be used to initialize TraceOptions.
const char kRecordUntilFull[] = "record-until-full";
const char kRecordContinuously[] = "record-continuously";
const char kRecordAsMuchAsPossible[] = "record-as-much-as-possible";
const char kTraceToConsole[] = "trace-to-console";
const char kEnableSampling[] = "enable-sampling";
const char kEnableSystrace[] = "enable-systrace";
const char kEnableArgumentFilter[] = "enable-argument-filter";

// String parameters that can be used to parse the trace config string.
const char kRecordModeParam[] = "record_mode";
const char kEnableSamplingParam[] = "enable_sampling";
const char kEnableSystraceParam[] = "enable_systrace";
const char kEnableArgumentFilterParam[] = "enable_argument_filter";
const char kIncludedCategoriesParam[] = "included_categories";
const char kExcludedCategoriesParam[] = "excluded_categories";
const char kSyntheticDelaysParam[] = "synthetic_delays";

const char kSyntheticDelayCategoryFilterPrefix[] = "DELAY(";

// String parameters that is used to parse memory dump config in trace config
// string.
const char kMemoryDumpConfigParam[] = "memory_dump_config";
const char kAllowedDumpModesParam[] = "allowed_dump_modes";
const char kTriggersParam[] = "triggers";
const char kPeriodicIntervalParam[] = "periodic_interval_ms";
const char kModeParam[] = "mode";
const char kHeapProfilerOptions[] = "heap_profiler_options";
const char kBreakdownThresholdBytes[] = "breakdown_threshold_bytes";

// String parameters used to parse category event filters.
const char kEventFiltersParam[] = "event_filters";
const char kFilterPredicateParam[] = "filter_predicate";
const char kFilterArgsParam[] = "filter_args";

// Default configuration of memory dumps.
const TraceConfig::MemoryDumpConfig::Trigger kDefaultHeavyMemoryDumpTrigger = {
    2000,  // periodic_interval_ms
    MemoryDumpLevelOfDetail::DETAILED};
const TraceConfig::MemoryDumpConfig::Trigger kDefaultLightMemoryDumpTrigger = {
    250,  // periodic_interval_ms
    MemoryDumpLevelOfDetail::LIGHT};

class ConvertableTraceConfigToTraceFormat
    : public base::trace_event::ConvertableToTraceFormat {
 public:
  explicit ConvertableTraceConfigToTraceFormat(const TraceConfig& trace_config)
      : trace_config_(trace_config) {}

  ~ConvertableTraceConfigToTraceFormat() override {}

  void AppendAsTraceFormat(std::string* out) const override {
    out->append(trace_config_.ToString());
  }

 private:
  const TraceConfig trace_config_;
};

std::set<MemoryDumpLevelOfDetail> GetDefaultAllowedMemoryDumpModes() {
  std::set<MemoryDumpLevelOfDetail> all_modes;
  for (uint32_t mode = static_cast<uint32_t>(MemoryDumpLevelOfDetail::FIRST);
       mode <= static_cast<uint32_t>(MemoryDumpLevelOfDetail::LAST); mode++) {
    all_modes.insert(static_cast<MemoryDumpLevelOfDetail>(mode));
  }
  return all_modes;
}

}  // namespace

TraceConfig::MemoryDumpConfig::HeapProfiler::HeapProfiler()
    : breakdown_threshold_bytes(kDefaultBreakdownThresholdBytes) {}

void TraceConfig::MemoryDumpConfig::HeapProfiler::Clear() {
  breakdown_threshold_bytes = kDefaultBreakdownThresholdBytes;
}

void TraceConfig::ResetMemoryDumpConfig(
    const TraceConfig::MemoryDumpConfig& memory_dump_config) {
  memory_dump_config_.Clear();
  memory_dump_config_ = memory_dump_config;
}

TraceConfig::MemoryDumpConfig::MemoryDumpConfig() {}

TraceConfig::MemoryDumpConfig::MemoryDumpConfig(
    const MemoryDumpConfig& other) = default;

TraceConfig::MemoryDumpConfig::~MemoryDumpConfig() {}

void TraceConfig::MemoryDumpConfig::Clear() {
  allowed_dump_modes.clear();
  triggers.clear();
  heap_profiler_options.Clear();
}

TraceConfig::EventFilterConfig::EventFilterConfig(
    const std::string& predicate_name)
    : predicate_name_(predicate_name) {}

TraceConfig::EventFilterConfig::~EventFilterConfig() {}

TraceConfig::EventFilterConfig::EventFilterConfig(const EventFilterConfig& tc) {
  *this = tc;
}

TraceConfig::EventFilterConfig& TraceConfig::EventFilterConfig::operator=(
    const TraceConfig::EventFilterConfig& rhs) {
  if (this == &rhs)
    return *this;

  predicate_name_ = rhs.predicate_name_;
  included_categories_ = rhs.included_categories_;
  excluded_categories_ = rhs.excluded_categories_;
  if (rhs.args_)
    args_ = rhs.args_->CreateDeepCopy();

  return *this;
}

void TraceConfig::EventFilterConfig::AddIncludedCategory(
    const std::string& category) {
  included_categories_.push_back(category);
}

void TraceConfig::EventFilterConfig::AddExcludedCategory(
    const std::string& category) {
  excluded_categories_.push_back(category);
}

void TraceConfig::EventFilterConfig::SetArgs(
    std::unique_ptr<base::DictionaryValue> args) {
  args_ = std::move(args);
}

bool TraceConfig::EventFilterConfig::IsCategoryGroupEnabled(
    const char* category_group_name) const {
  CStringTokenizer category_group_tokens(
      category_group_name, category_group_name + strlen(category_group_name),
      ",");
  while (category_group_tokens.GetNext()) {
    std::string category_group_token = category_group_tokens.token();

    for (const auto& excluded_category : excluded_categories_) {
      if (base::MatchPattern(category_group_token, excluded_category)) {
        return false;
      }
    }

    for (const auto& included_category : included_categories_) {
      if (base::MatchPattern(category_group_token, included_category)) {
        return true;
      }
    }
  }

  return false;
}

TraceConfig::TraceConfig() {
  InitializeDefault();
}

TraceConfig::TraceConfig(StringPiece category_filter_string,
                         StringPiece trace_options_string) {
  InitializeFromStrings(category_filter_string, trace_options_string);
}

TraceConfig::TraceConfig(StringPiece category_filter_string,
                         TraceRecordMode record_mode) {
  std::string trace_options_string;
  switch (record_mode) {
    case RECORD_UNTIL_FULL:
      trace_options_string = kRecordUntilFull;
      break;
    case RECORD_CONTINUOUSLY:
      trace_options_string = kRecordContinuously;
      break;
    case RECORD_AS_MUCH_AS_POSSIBLE:
      trace_options_string = kRecordAsMuchAsPossible;
      break;
    case ECHO_TO_CONSOLE:
      trace_options_string = kTraceToConsole;
      break;
    default:
      NOTREACHED();
  }
  InitializeFromStrings(category_filter_string, trace_options_string);
}

TraceConfig::TraceConfig(const DictionaryValue& config) {
  InitializeFromConfigDict(config);
}

TraceConfig::TraceConfig(StringPiece config_string) {
  if (!config_string.empty())
    InitializeFromConfigString(config_string);
  else
    InitializeDefault();
}

TraceConfig::TraceConfig(const TraceConfig& tc)
    : record_mode_(tc.record_mode_),
      enable_sampling_(tc.enable_sampling_),
      enable_systrace_(tc.enable_systrace_),
      enable_argument_filter_(tc.enable_argument_filter_),
      memory_dump_config_(tc.memory_dump_config_),
      included_categories_(tc.included_categories_),
      disabled_categories_(tc.disabled_categories_),
      excluded_categories_(tc.excluded_categories_),
      synthetic_delays_(tc.synthetic_delays_),
      event_filters_(tc.event_filters_) {}

TraceConfig::~TraceConfig() {
}

TraceConfig& TraceConfig::operator=(const TraceConfig& rhs) {
  if (this == &rhs)
    return *this;

  record_mode_ = rhs.record_mode_;
  enable_sampling_ = rhs.enable_sampling_;
  enable_systrace_ = rhs.enable_systrace_;
  enable_argument_filter_ = rhs.enable_argument_filter_;
  memory_dump_config_ = rhs.memory_dump_config_;
  included_categories_ = rhs.included_categories_;
  disabled_categories_ = rhs.disabled_categories_;
  excluded_categories_ = rhs.excluded_categories_;
  synthetic_delays_ = rhs.synthetic_delays_;
  event_filters_ = rhs.event_filters_;
  return *this;
}

const TraceConfig::StringList& TraceConfig::GetSyntheticDelayValues() const {
  return synthetic_delays_;
}

std::string TraceConfig::ToString() const {
  std::unique_ptr<DictionaryValue> dict = ToDict();
  std::string json;
  JSONWriter::Write(*dict, &json);
  return json;
}

std::unique_ptr<ConvertableToTraceFormat>
TraceConfig::AsConvertableToTraceFormat() const {
  return MakeUnique<ConvertableTraceConfigToTraceFormat>(*this);
}

std::string TraceConfig::ToCategoryFilterString() const {
  std::string filter_string;
  WriteCategoryFilterString(included_categories_, &filter_string, true);
  WriteCategoryFilterString(disabled_categories_, &filter_string, true);
  WriteCategoryFilterString(excluded_categories_, &filter_string, false);
  WriteCategoryFilterString(synthetic_delays_, &filter_string);
  return filter_string;
}

bool TraceConfig::IsCategoryGroupEnabled(
    const char* category_group_name) const {
  // TraceLog should call this method only as part of enabling/disabling
  // categories.

  bool had_enabled_by_default = false;
  DCHECK(category_group_name);
  std::string category_group_name_str = category_group_name;
  StringTokenizer category_group_tokens(category_group_name_str, ",");
  while (category_group_tokens.GetNext()) {
    std::string category_group_token = category_group_tokens.token();
    // Don't allow empty tokens, nor tokens with leading or trailing space.
    DCHECK(!TraceConfig::IsEmptyOrContainsLeadingOrTrailingWhitespace(
               category_group_token))
        << "Disallowed category string";
    if (IsCategoryEnabled(category_group_token.c_str()))
      return true;

    if (!MatchPattern(category_group_token, TRACE_DISABLED_BY_DEFAULT("*")))
      had_enabled_by_default = true;
  }
  // Do a second pass to check for explicitly disabled categories
  // (those explicitly enabled have priority due to first pass).
  category_group_tokens.Reset();
  bool category_group_disabled = false;
  while (category_group_tokens.GetNext()) {
    std::string category_group_token = category_group_tokens.token();
    for (const std::string& category : excluded_categories_) {
      if (MatchPattern(category_group_token, category)) {
        // Current token of category_group_name is present in excluded_list.
        // Flag the exclusion and proceed further to check if any of the
        // remaining categories of category_group_name is not present in the
        // excluded_ list.
        category_group_disabled = true;
        break;
      }
      // One of the category of category_group_name is not present in
      // excluded_ list. So, if it's not a disabled-by-default category,
      // it has to be included_ list. Enable the category_group_name
      // for recording.
      if (!MatchPattern(category_group_token, TRACE_DISABLED_BY_DEFAULT("*"))) {
        category_group_disabled = false;
      }
    }
    // One of the categories present in category_group_name is not present in
    // excluded_ list. Implies this category_group_name group can be enabled
    // for recording, since one of its groups is enabled for recording.
    if (!category_group_disabled)
      break;
  }
  // If the category group is not excluded, and there are no included patterns
  // we consider this category group enabled, as long as it had categories
  // other than disabled-by-default.
  return !category_group_disabled && had_enabled_by_default &&
         included_categories_.empty();
}

void TraceConfig::Merge(const TraceConfig& config) {
  if (record_mode_ != config.record_mode_
      || enable_sampling_ != config.enable_sampling_
      || enable_systrace_ != config.enable_systrace_
      || enable_argument_filter_ != config.enable_argument_filter_) {
    DLOG(ERROR) << "Attempting to merge trace config with a different "
                << "set of options.";
  }

  // Keep included patterns only if both filters have an included entry.
  // Otherwise, one of the filter was specifying "*" and we want to honor the
  // broadest filter.
  if (HasIncludedPatterns() && config.HasIncludedPatterns()) {
    included_categories_.insert(included_categories_.end(),
                                config.included_categories_.begin(),
                                config.included_categories_.end());
  } else {
    included_categories_.clear();
  }

  memory_dump_config_.triggers.insert(memory_dump_config_.triggers.end(),
                             config.memory_dump_config_.triggers.begin(),
                             config.memory_dump_config_.triggers.end());

  disabled_categories_.insert(disabled_categories_.end(),
                              config.disabled_categories_.begin(),
                              config.disabled_categories_.end());
  excluded_categories_.insert(excluded_categories_.end(),
                              config.excluded_categories_.begin(),
                              config.excluded_categories_.end());
  synthetic_delays_.insert(synthetic_delays_.end(),
                           config.synthetic_delays_.begin(),
                           config.synthetic_delays_.end());
}

void TraceConfig::Clear() {
  record_mode_ = RECORD_UNTIL_FULL;
  enable_sampling_ = false;
  enable_systrace_ = false;
  enable_argument_filter_ = false;
  included_categories_.clear();
  disabled_categories_.clear();
  excluded_categories_.clear();
  synthetic_delays_.clear();
  memory_dump_config_.Clear();
  event_filters_.clear();
}

void TraceConfig::InitializeDefault() {
  record_mode_ = RECORD_UNTIL_FULL;
  enable_sampling_ = false;
  enable_systrace_ = false;
  enable_argument_filter_ = false;
}

void TraceConfig::InitializeFromConfigDict(const DictionaryValue& dict) {
  record_mode_ = RECORD_UNTIL_FULL;
  std::string record_mode;
  if (dict.GetString(kRecordModeParam, &record_mode)) {
    if (record_mode == kRecordUntilFull) {
      record_mode_ = RECORD_UNTIL_FULL;
    } else if (record_mode == kRecordContinuously) {
      record_mode_ = RECORD_CONTINUOUSLY;
    } else if (record_mode == kTraceToConsole) {
      record_mode_ = ECHO_TO_CONSOLE;
    } else if (record_mode == kRecordAsMuchAsPossible) {
      record_mode_ = RECORD_AS_MUCH_AS_POSSIBLE;
    }
  }

  bool val;
  enable_sampling_ = dict.GetBoolean(kEnableSamplingParam, &val) ? val : false;
  enable_systrace_ = dict.GetBoolean(kEnableSystraceParam, &val) ? val : false;
  enable_argument_filter_ =
      dict.GetBoolean(kEnableArgumentFilterParam, &val) ? val : false;

  const ListValue* category_list = nullptr;
  if (dict.GetList(kIncludedCategoriesParam, &category_list))
    SetCategoriesFromIncludedList(*category_list);
  if (dict.GetList(kExcludedCategoriesParam, &category_list))
    SetCategoriesFromExcludedList(*category_list);
  if (dict.GetList(kSyntheticDelaysParam, &category_list))
    SetSyntheticDelaysFromList(*category_list);

  if (IsCategoryEnabled(MemoryDumpManager::kTraceCategory)) {
    // If dump triggers not set, the client is using the legacy with just
    // category enabled. So, use the default periodic dump config.
    const DictionaryValue* memory_dump_config = nullptr;
    if (dict.GetDictionary(kMemoryDumpConfigParam, &memory_dump_config))
      SetMemoryDumpConfigFromConfigDict(*memory_dump_config);
    else
      SetDefaultMemoryDumpConfig();
  }

  const base::ListValue* category_event_filters = nullptr;
  if (dict.GetList(kEventFiltersParam, &category_event_filters))
    SetEventFilters(*category_event_filters);
}

void TraceConfig::InitializeFromConfigString(StringPiece config_string) {
  auto dict = DictionaryValue::From(JSONReader::Read(config_string));
  if (dict)
    InitializeFromConfigDict(*dict);
  else
    InitializeDefault();
}

void TraceConfig::InitializeFromStrings(StringPiece category_filter_string,
                                        StringPiece trace_options_string) {
  if (!category_filter_string.empty()) {
    std::vector<std::string> split = SplitString(
        category_filter_string, ",", TRIM_WHITESPACE, SPLIT_WANT_ALL);
    for (const std::string& category : split) {
      // Ignore empty categories.
      if (category.empty())
        continue;
      // Synthetic delays are of the form 'DELAY(delay;option;option;...)'.
      if (StartsWith(category, kSyntheticDelayCategoryFilterPrefix,
                     CompareCase::SENSITIVE) &&
          category.back() == ')') {
        std::string synthetic_category = category.substr(
            strlen(kSyntheticDelayCategoryFilterPrefix),
            category.size() - strlen(kSyntheticDelayCategoryFilterPrefix) - 1);
        size_t name_length = synthetic_category.find(';');
        if (name_length != std::string::npos && name_length > 0 &&
            name_length != synthetic_category.size() - 1) {
          synthetic_delays_.push_back(synthetic_category);
        }
      } else if (category.front() == '-') {
        // Excluded categories start with '-'.
        // Remove '-' from category string.
        excluded_categories_.push_back(category.substr(1));
      } else if (category.compare(0, strlen(TRACE_DISABLED_BY_DEFAULT("")),
                                  TRACE_DISABLED_BY_DEFAULT("")) == 0) {
        disabled_categories_.push_back(category);
      } else {
        included_categories_.push_back(category);
      }
    }
  }

  record_mode_ = RECORD_UNTIL_FULL;
  enable_sampling_ = false;
  enable_systrace_ = false;
  enable_argument_filter_ = false;
  if (!trace_options_string.empty()) {
    std::vector<std::string> split =
        SplitString(trace_options_string, ",", TRIM_WHITESPACE, SPLIT_WANT_ALL);
    for (const std::string& token : split) {
      if (token == kRecordUntilFull) {
        record_mode_ = RECORD_UNTIL_FULL;
      } else if (token == kRecordContinuously) {
        record_mode_ = RECORD_CONTINUOUSLY;
      } else if (token == kTraceToConsole) {
        record_mode_ = ECHO_TO_CONSOLE;
      } else if (token == kRecordAsMuchAsPossible) {
        record_mode_ = RECORD_AS_MUCH_AS_POSSIBLE;
      } else if (token == kEnableSampling) {
        enable_sampling_ = true;
      } else if (token == kEnableSystrace) {
        enable_systrace_ = true;
      } else if (token == kEnableArgumentFilter) {
        enable_argument_filter_ = true;
      }
    }
  }

  if (IsCategoryEnabled(MemoryDumpManager::kTraceCategory)) {
    SetDefaultMemoryDumpConfig();
  }
}

void TraceConfig::SetCategoriesFromIncludedList(
    const ListValue& included_list) {
  included_categories_.clear();
  for (size_t i = 0; i < included_list.GetSize(); ++i) {
    std::string category;
    if (!included_list.GetString(i, &category))
      continue;
    if (category.compare(0, strlen(TRACE_DISABLED_BY_DEFAULT("")),
                         TRACE_DISABLED_BY_DEFAULT("")) == 0) {
      disabled_categories_.push_back(category);
    } else {
      included_categories_.push_back(category);
    }
  }
}

void TraceConfig::SetCategoriesFromExcludedList(
    const ListValue& excluded_list) {
  excluded_categories_.clear();
  for (size_t i = 0; i < excluded_list.GetSize(); ++i) {
    std::string category;
    if (excluded_list.GetString(i, &category))
      excluded_categories_.push_back(category);
  }
}

void TraceConfig::SetSyntheticDelaysFromList(const ListValue& list) {
  synthetic_delays_.clear();
  for (size_t i = 0; i < list.GetSize(); ++i) {
    std::string delay;
    if (!list.GetString(i, &delay))
      continue;
    // Synthetic delays are of the form "delay;option;option;...".
    size_t name_length = delay.find(';');
    if (name_length != std::string::npos && name_length > 0 &&
        name_length != delay.size() - 1) {
      synthetic_delays_.push_back(delay);
    }
  }
}

void TraceConfig::AddCategoryToDict(DictionaryValue* dict,
                                    const char* param,
                                    const StringList& categories) const {
  if (categories.empty())
    return;

  auto list = MakeUnique<ListValue>();
  for (const std::string& category : categories)
    list->AppendString(category);
  dict->Set(param, std::move(list));
}

void TraceConfig::SetMemoryDumpConfigFromConfigDict(
    const DictionaryValue& memory_dump_config) {
  // Set allowed dump modes.
  memory_dump_config_.allowed_dump_modes.clear();
  const ListValue* allowed_modes_list;
  if (memory_dump_config.GetList(kAllowedDumpModesParam, &allowed_modes_list)) {
    for (size_t i = 0; i < allowed_modes_list->GetSize(); ++i) {
      std::string level_of_detail_str;
      allowed_modes_list->GetString(i, &level_of_detail_str);
      memory_dump_config_.allowed_dump_modes.insert(
          StringToMemoryDumpLevelOfDetail(level_of_detail_str));
    }
  } else {
    // If allowed modes param is not given then allow all modes by default.
    memory_dump_config_.allowed_dump_modes = GetDefaultAllowedMemoryDumpModes();
  }

  // Set triggers
  memory_dump_config_.triggers.clear();
  const ListValue* trigger_list = nullptr;
  if (memory_dump_config.GetList(kTriggersParam, &trigger_list) &&
      trigger_list->GetSize() > 0) {
    for (size_t i = 0; i < trigger_list->GetSize(); ++i) {
      const DictionaryValue* trigger = nullptr;
      if (!trigger_list->GetDictionary(i, &trigger))
        continue;

      int interval = 0;
      if (!trigger->GetInteger(kPeriodicIntervalParam, &interval))
        continue;

      DCHECK_GT(interval, 0);
      MemoryDumpConfig::Trigger dump_config;
      dump_config.periodic_interval_ms = static_cast<uint32_t>(interval);
      std::string level_of_detail_str;
      trigger->GetString(kModeParam, &level_of_detail_str);
      dump_config.level_of_detail =
          StringToMemoryDumpLevelOfDetail(level_of_detail_str);
      memory_dump_config_.triggers.push_back(dump_config);
    }
  }

  // Set heap profiler options
  const DictionaryValue* heap_profiler_options = nullptr;
  if (memory_dump_config.GetDictionary(kHeapProfilerOptions,
                                       &heap_profiler_options)) {
    int min_size_bytes = 0;
    if (heap_profiler_options->GetInteger(kBreakdownThresholdBytes,
                                         &min_size_bytes)
        && min_size_bytes >= 0) {
      memory_dump_config_.heap_profiler_options.breakdown_threshold_bytes =
          static_cast<size_t>(min_size_bytes);
    } else {
      memory_dump_config_.heap_profiler_options.breakdown_threshold_bytes =
          MemoryDumpConfig::HeapProfiler::kDefaultBreakdownThresholdBytes;
    }
  }
}

void TraceConfig::SetDefaultMemoryDumpConfig() {
  memory_dump_config_.Clear();
  memory_dump_config_.triggers.push_back(kDefaultHeavyMemoryDumpTrigger);
  memory_dump_config_.triggers.push_back(kDefaultLightMemoryDumpTrigger);
  memory_dump_config_.allowed_dump_modes = GetDefaultAllowedMemoryDumpModes();

  if (AllocationContextTracker::capture_mode() ==
      AllocationContextTracker::CaptureMode::PSEUDO_STACK) {
    for (const auto& filter : event_filters_) {
      if (filter.predicate_name() ==
          TraceLog::TraceEventFilter::kHeapProfilerPredicate)
        return;
    }
    // Adds a filter predicate to filter all categories for the heap profiler.
    // Note that the heap profiler predicate does not filter-out any events.
    EventFilterConfig heap_profiler_config(
        TraceLog::TraceEventFilter::kHeapProfilerPredicate);
    heap_profiler_config.AddIncludedCategory("*");
    heap_profiler_config.AddIncludedCategory(MemoryDumpManager::kTraceCategory);
    event_filters_.push_back(heap_profiler_config);
  }
}

void TraceConfig::SetEventFilters(
    const base::ListValue& category_event_filters) {
  event_filters_.clear();

  for (size_t event_filter_index = 0;
       event_filter_index < category_event_filters.GetSize();
       ++event_filter_index) {
    const base::DictionaryValue* event_filter = nullptr;
    if (!category_event_filters.GetDictionary(event_filter_index,
                                              &event_filter))
      continue;

    std::string predicate_name;
    CHECK(event_filter->GetString(kFilterPredicateParam, &predicate_name))
        << "Invalid predicate name in category event filter.";

    EventFilterConfig new_config(predicate_name);
    const base::ListValue* included_list = nullptr;
    CHECK(event_filter->GetList(kIncludedCategoriesParam, &included_list))
        << "Missing included_categories in category event filter.";

    for (size_t i = 0; i < included_list->GetSize(); ++i) {
      std::string category;
      if (included_list->GetString(i, &category))
        new_config.AddIncludedCategory(category);
    }

    const base::ListValue* excluded_list = nullptr;
    if (event_filter->GetList(kExcludedCategoriesParam, &excluded_list)) {
      for (size_t i = 0; i < excluded_list->GetSize(); ++i) {
        std::string category;
        if (excluded_list->GetString(i, &category))
          new_config.AddExcludedCategory(category);
      }
    }

    const base::DictionaryValue* args_dict = nullptr;
    if (event_filter->GetDictionary(kFilterArgsParam, &args_dict))
      new_config.SetArgs(args_dict->CreateDeepCopy());

    event_filters_.push_back(new_config);
  }
}

std::unique_ptr<DictionaryValue> TraceConfig::ToDict() const {
  auto dict = MakeUnique<DictionaryValue>();
  switch (record_mode_) {
    case RECORD_UNTIL_FULL:
      dict->SetString(kRecordModeParam, kRecordUntilFull);
      break;
    case RECORD_CONTINUOUSLY:
      dict->SetString(kRecordModeParam, kRecordContinuously);
      break;
    case RECORD_AS_MUCH_AS_POSSIBLE:
      dict->SetString(kRecordModeParam, kRecordAsMuchAsPossible);
      break;
    case ECHO_TO_CONSOLE:
      dict->SetString(kRecordModeParam, kTraceToConsole);
      break;
    default:
      NOTREACHED();
  }

  dict->SetBoolean(kEnableSamplingParam, enable_sampling_);
  dict->SetBoolean(kEnableSystraceParam, enable_systrace_);
  dict->SetBoolean(kEnableArgumentFilterParam, enable_argument_filter_);

  StringList categories(included_categories_);
  categories.insert(categories.end(),
                    disabled_categories_.begin(),
                    disabled_categories_.end());
  AddCategoryToDict(dict.get(), kIncludedCategoriesParam, categories);
  AddCategoryToDict(dict.get(), kExcludedCategoriesParam, excluded_categories_);
  AddCategoryToDict(dict.get(), kSyntheticDelaysParam, synthetic_delays_);

  if (!event_filters_.empty()) {
    std::unique_ptr<base::ListValue> filter_list(new base::ListValue());
    for (const EventFilterConfig& filter : event_filters_) {
      std::unique_ptr<base::DictionaryValue> filter_dict(
          new base::DictionaryValue());
      filter_dict->SetString(kFilterPredicateParam, filter.predicate_name());

      std::unique_ptr<base::ListValue> included_categories_list(
          new base::ListValue());
      for (const std::string& included_category : filter.included_categories())
        included_categories_list->AppendString(included_category);

      filter_dict->Set(kIncludedCategoriesParam,
                       std::move(included_categories_list));

      if (!filter.excluded_categories().empty()) {
        std::unique_ptr<base::ListValue> excluded_categories_list(
            new base::ListValue());
        for (const std::string& excluded_category :
             filter.excluded_categories())
          excluded_categories_list->AppendString(excluded_category);

        filter_dict->Set(kExcludedCategoriesParam,
                         std::move(excluded_categories_list));
      }

      if (filter.filter_args())
        filter_dict->Set(kFilterArgsParam,
                         filter.filter_args()->CreateDeepCopy());

      filter_list->Append(std::move(filter_dict));
    }
    dict->Set(kEventFiltersParam, std::move(filter_list));
  }

  if (IsCategoryEnabled(MemoryDumpManager::kTraceCategory)) {
    auto allowed_modes = MakeUnique<ListValue>();
    for (auto dump_mode : memory_dump_config_.allowed_dump_modes)
      allowed_modes->AppendString(MemoryDumpLevelOfDetailToString(dump_mode));

    auto memory_dump_config = MakeUnique<DictionaryValue>();
    memory_dump_config->Set(kAllowedDumpModesParam, std::move(allowed_modes));

    auto triggers_list = MakeUnique<ListValue>();
    for (const auto& config : memory_dump_config_.triggers) {
      auto trigger_dict = MakeUnique<DictionaryValue>();
      trigger_dict->SetInteger(kPeriodicIntervalParam,
                               static_cast<int>(config.periodic_interval_ms));
      trigger_dict->SetString(
          kModeParam, MemoryDumpLevelOfDetailToString(config.level_of_detail));
      triggers_list->Append(std::move(trigger_dict));
    }

    // Empty triggers will still be specified explicitly since it means that
    // the periodic dumps are not enabled.
    memory_dump_config->Set(kTriggersParam, std::move(triggers_list));

    if (memory_dump_config_.heap_profiler_options.breakdown_threshold_bytes !=
        MemoryDumpConfig::HeapProfiler::kDefaultBreakdownThresholdBytes) {
      auto options = MakeUnique<DictionaryValue>();
      options->SetInteger(
          kBreakdownThresholdBytes,
          memory_dump_config_.heap_profiler_options.breakdown_threshold_bytes);
      memory_dump_config->Set(kHeapProfilerOptions, std::move(options));
    }
    dict->Set(kMemoryDumpConfigParam, std::move(memory_dump_config));
  }
  return dict;
}

std::string TraceConfig::ToTraceOptionsString() const {
  std::string ret;
  switch (record_mode_) {
    case RECORD_UNTIL_FULL:
      ret = kRecordUntilFull;
      break;
    case RECORD_CONTINUOUSLY:
      ret = kRecordContinuously;
      break;
    case RECORD_AS_MUCH_AS_POSSIBLE:
      ret = kRecordAsMuchAsPossible;
      break;
    case ECHO_TO_CONSOLE:
      ret = kTraceToConsole;
      break;
    default:
      NOTREACHED();
  }
  if (enable_sampling_)
    ret = ret + "," + kEnableSampling;
  if (enable_systrace_)
    ret = ret + "," + kEnableSystrace;
  if (enable_argument_filter_)
    ret = ret + "," + kEnableArgumentFilter;
  return ret;
}

void TraceConfig::WriteCategoryFilterString(const StringList& values,
                                            std::string* out,
                                            bool included) const {
  bool prepend_comma = !out->empty();
  int token_cnt = 0;
  for (const std::string& category : values) {
    if (token_cnt > 0 || prepend_comma)
      StringAppendF(out, ",");
    StringAppendF(out, "%s%s", (included ? "" : "-"), category.c_str());
    ++token_cnt;
  }
}

void TraceConfig::WriteCategoryFilterString(const StringList& delays,
                                            std::string* out) const {
  bool prepend_comma = !out->empty();
  int token_cnt = 0;
  for (const std::string& category : delays) {
    if (token_cnt > 0 || prepend_comma)
      StringAppendF(out, ",");
    StringAppendF(out, "%s%s)", kSyntheticDelayCategoryFilterPrefix,
                  category.c_str());
    ++token_cnt;
  }
}

bool TraceConfig::IsCategoryEnabled(const char* category_name) const {
  // Check the disabled- filters and the disabled-* wildcard first so that a
  // "*" filter does not include the disabled.
  for (const std::string& category : disabled_categories_) {
    if (MatchPattern(category_name, category))
      return true;
  }

  if (MatchPattern(category_name, TRACE_DISABLED_BY_DEFAULT("*")))
    return false;

  for (const std::string& category : included_categories_) {
    if (MatchPattern(category_name, category))
      return true;
  }

  return false;
}

bool TraceConfig::IsEmptyOrContainsLeadingOrTrailingWhitespace(
    StringPiece str) {
  return str.empty() || str.front() == ' ' || str.back() == ' ';
}

bool TraceConfig::HasIncludedPatterns() const {
  return !included_categories_.empty();
}

}  // namespace trace_event
}  // namespace base

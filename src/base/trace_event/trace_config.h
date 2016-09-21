// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_TRACE_CONFIG_H_
#define BASE_TRACE_EVENT_TRACE_CONFIG_H_

#include <stdint.h>

#include <set>
#include <string>
#include <vector>

#include "base/base_export.h"
#include "base/gtest_prod_util.h"
#include "base/strings/string_piece.h"
#include "base/trace_event/memory_dump_request_args.h"
#include "base/values.h"

namespace base {
namespace trace_event {

class ConvertableToTraceFormat;

// Options determines how the trace buffer stores data.
enum TraceRecordMode {
  // Record until the trace buffer is full.
  RECORD_UNTIL_FULL,

  // Record until the user ends the trace. The trace buffer is a fixed size
  // and we use it as a ring buffer during recording.
  RECORD_CONTINUOUSLY,

  // Record until the trace buffer is full, but with a huge buffer size.
  RECORD_AS_MUCH_AS_POSSIBLE,

  // Echo to console. Events are discarded.
  ECHO_TO_CONSOLE,
};

class BASE_EXPORT TraceConfig {
 public:
  using StringList = std::vector<std::string>;

  // Specifies the memory dump config for tracing.
  // Used only when "memory-infra" category is enabled.
  struct BASE_EXPORT MemoryDumpConfig {
    MemoryDumpConfig();
    MemoryDumpConfig(const MemoryDumpConfig& other);
    ~MemoryDumpConfig();

    // Specifies the triggers in the memory dump config.
    struct Trigger {
      uint32_t periodic_interval_ms;
      MemoryDumpLevelOfDetail level_of_detail;
    };

    // Specifies the configuration options for the heap profiler.
    struct HeapProfiler {
      // Default value for |breakdown_threshold_bytes|.
      enum { kDefaultBreakdownThresholdBytes = 1024 };

      HeapProfiler();

      // Reset the options to default.
      void Clear();

      uint32_t breakdown_threshold_bytes;
    };

    // Reset the values in the config.
    void Clear();

    // Set of memory dump modes allowed for the tracing session. The explicitly
    // triggered dumps will be successful only if the dump mode is allowed in
    // the config.
    std::set<MemoryDumpLevelOfDetail> allowed_dump_modes;

    std::vector<Trigger> triggers;
    HeapProfiler heap_profiler_options;
  };

  class EventFilterConfig {
   public:
    EventFilterConfig(const std::string& predicate_name);
    EventFilterConfig(const EventFilterConfig& tc);

    ~EventFilterConfig();

    EventFilterConfig& operator=(const EventFilterConfig& rhs);

    void AddIncludedCategory(const std::string& category);
    void AddExcludedCategory(const std::string& category);
    void SetArgs(std::unique_ptr<base::DictionaryValue> args);

    bool IsCategoryGroupEnabled(const char* category_group_name) const;

    const std::string& predicate_name() const { return predicate_name_; }
    base::DictionaryValue* filter_args() const { return args_.get(); }
    const StringList& included_categories() const {
      return included_categories_;
    }
    const StringList& excluded_categories() const {
      return excluded_categories_;
    }

   private:
    std::string predicate_name_;
    StringList included_categories_;
    StringList excluded_categories_;
    std::unique_ptr<base::DictionaryValue> args_;
  };
  typedef std::vector<EventFilterConfig> EventFilters;

  TraceConfig();

  // Create TraceConfig object from category filter and trace options strings.
  //
  // |category_filter_string| is a comma-delimited list of category wildcards.
  // A category can have an optional '-' prefix to make it an excluded category.
  // All the same rules apply above, so for example, having both included and
  // excluded categories in the same list would not be supported.
  //
  // Category filters can also be used to configure synthetic delays.
  //
  // |trace_options_string| is a comma-delimited list of trace options.
  // Possible options are: "record-until-full", "record-continuously",
  // "record-as-much-as-possible", "trace-to-console", "enable-sampling",
  // "enable-systrace" and "enable-argument-filter".
  // The first 4 options are trace recoding modes and hence
  // mutually exclusive. If more than one trace recording modes appear in the
  // options_string, the last one takes precedence. If none of the trace
  // recording mode is specified, recording mode is RECORD_UNTIL_FULL.
  //
  // The trace option will first be reset to the default option
  // (record_mode set to RECORD_UNTIL_FULL, enable_sampling, enable_systrace,
  // and enable_argument_filter set to false) before options parsed from
  // |trace_options_string| are applied on it. If |trace_options_string| is
  // invalid, the final state of trace options is undefined.
  //
  // Example: TraceConfig("test_MyTest*", "record-until-full");
  // Example: TraceConfig("test_MyTest*,test_OtherStuff",
  //                      "record-continuously, enable-sampling");
  // Example: TraceConfig("-excluded_category1,-excluded_category2",
  //                      "record-until-full, trace-to-console");
  //          would set ECHO_TO_CONSOLE as the recording mode.
  // Example: TraceConfig("-*,webkit", "");
  //          would disable everything but webkit; and use default options.
  // Example: TraceConfig("-webkit", "");
  //          would enable everything but webkit; and use default options.
  // Example: TraceConfig("DELAY(gpu.PresentingFrame;16)", "");
  //          would make swap buffers always take at least 16 ms; and use
  //          default options.
  // Example: TraceConfig("DELAY(gpu.PresentingFrame;16;oneshot)", "");
  //          would make swap buffers take at least 16 ms the first time it is
  //          called; and use default options.
  // Example: TraceConfig("DELAY(gpu.PresentingFrame;16;alternating)", "");
  //          would make swap buffers take at least 16 ms every other time it
  //          is called; and use default options.
  TraceConfig(StringPiece category_filter_string,
              StringPiece trace_options_string);

  TraceConfig(StringPiece category_filter_string, TraceRecordMode record_mode);

  // Create TraceConfig object from the trace config string.
  //
  // |config_string| is a dictionary formatted as a JSON string, containing both
  // category filters and trace options.
  //
  // Example:
  //   {
  //     "record_mode": "record-continuously",
  //     "enable_sampling": true,
  //     "enable_systrace": true,
  //     "enable_argument_filter": true,
  //     "included_categories": ["included",
  //                             "inc_pattern*",
  //                             "disabled-by-default-memory-infra"],
  //     "excluded_categories": ["excluded", "exc_pattern*"],
  //     "synthetic_delays": ["test.Delay1;16", "test.Delay2;32"],
  //     "memory_dump_config": {
  //       "triggers": [
  //         {
  //           "mode": "detailed",
  //           "periodic_interval_ms": 2000
  //         }
  //       ]
  //     }
  //   }
  //
  // Note: memory_dump_config can be specified only if
  // disabled-by-default-memory-infra category is enabled.
  explicit TraceConfig(StringPiece config_string);

  // Functionally identical to the above, but takes a parsed dictionary as input
  // instead of its JSON serialization.
  explicit TraceConfig(const DictionaryValue& config);

  TraceConfig(const TraceConfig& tc);

  ~TraceConfig();

  TraceConfig& operator=(const TraceConfig& rhs);

  // Return a list of the synthetic delays specified in this category filter.
  const StringList& GetSyntheticDelayValues() const;

  TraceRecordMode GetTraceRecordMode() const { return record_mode_; }
  bool IsSamplingEnabled() const { return enable_sampling_; }
  bool IsSystraceEnabled() const { return enable_systrace_; }
  bool IsArgumentFilterEnabled() const { return enable_argument_filter_; }

  void SetTraceRecordMode(TraceRecordMode mode) { record_mode_ = mode; }
  void EnableSampling() { enable_sampling_ = true; }
  void EnableSystrace() { enable_systrace_ = true; }
  void EnableArgumentFilter() { enable_argument_filter_ = true; }

  // Writes the string representation of the TraceConfig. The string is JSON
  // formatted.
  std::string ToString() const;

  // Returns a copy of the TraceConfig wrapped in a ConvertableToTraceFormat
  std::unique_ptr<ConvertableToTraceFormat> AsConvertableToTraceFormat() const;

  // Write the string representation of the CategoryFilter part.
  std::string ToCategoryFilterString() const;

  // Returns true if at least one category in the list is enabled by this
  // trace config. This is used to determine if the category filters are
  // enabled in the TRACE_* macros.
  bool IsCategoryGroupEnabled(const char* category_group_name) const;

  // Merges config with the current TraceConfig
  void Merge(const TraceConfig& config);

  void Clear();

  // Clears and resets the memory dump config.
  void ResetMemoryDumpConfig(const MemoryDumpConfig& memory_dump_config);

  const MemoryDumpConfig& memory_dump_config() const {
    return memory_dump_config_;
  }

  const EventFilters& event_filters() const { return event_filters_; }

 private:
  FRIEND_TEST_ALL_PREFIXES(TraceConfigTest, TraceConfigFromValidLegacyFormat);
  FRIEND_TEST_ALL_PREFIXES(TraceConfigTest,
                           TraceConfigFromInvalidLegacyStrings);
  FRIEND_TEST_ALL_PREFIXES(TraceConfigTest, TraceConfigFromValidString);
  FRIEND_TEST_ALL_PREFIXES(TraceConfigTest, TraceConfigFromInvalidString);
  FRIEND_TEST_ALL_PREFIXES(TraceConfigTest,
                           IsEmptyOrContainsLeadingOrTrailingWhitespace);
  FRIEND_TEST_ALL_PREFIXES(TraceConfigTest, TraceConfigFromMemoryConfigString);
  FRIEND_TEST_ALL_PREFIXES(TraceConfigTest, LegacyStringToMemoryDumpConfig);
  FRIEND_TEST_ALL_PREFIXES(TraceConfigTest, EmptyMemoryDumpConfigTest);
  FRIEND_TEST_ALL_PREFIXES(TraceConfigTest,
                           EmptyAndAsteriskCategoryFilterString);

  // The default trace config, used when none is provided.
  // Allows all non-disabled-by-default categories through, except if they end
  // in the suffix 'Debug' or 'Test'.
  void InitializeDefault();

  // Initialize from a config dictionary.
  void InitializeFromConfigDict(const DictionaryValue& dict);

  // Initialize from a config string.
  void InitializeFromConfigString(StringPiece config_string);

  // Initialize from category filter and trace options strings
  void InitializeFromStrings(StringPiece category_filter_string,
                             StringPiece trace_options_string);

  void SetCategoriesFromIncludedList(const ListValue& included_list);
  void SetCategoriesFromExcludedList(const ListValue& excluded_list);
  void SetSyntheticDelaysFromList(const ListValue& list);
  void AddCategoryToDict(DictionaryValue* dict,
                         const char* param,
                         const StringList& categories) const;

  void SetMemoryDumpConfigFromConfigDict(
      const DictionaryValue& memory_dump_config);
  void SetDefaultMemoryDumpConfig();

  void SetEventFilters(const base::ListValue& event_filters);
  std::unique_ptr<DictionaryValue> ToDict() const;

  std::string ToTraceOptionsString() const;

  void WriteCategoryFilterString(const StringList& values,
                                 std::string* out,
                                 bool included) const;
  void WriteCategoryFilterString(const StringList& delays,
                                 std::string* out) const;

  // Returns true if the category is enabled according to this trace config.
  // This tells whether a category is enabled from the TraceConfig's
  // perspective. Please refer to IsCategoryGroupEnabled() to determine if a
  // category is enabled from the tracing runtime's perspective.
  bool IsCategoryEnabled(const char* category_name) const;

  static bool IsEmptyOrContainsLeadingOrTrailingWhitespace(StringPiece str);

  bool HasIncludedPatterns() const;

  TraceRecordMode record_mode_;
  bool enable_sampling_ : 1;
  bool enable_systrace_ : 1;
  bool enable_argument_filter_ : 1;

  MemoryDumpConfig memory_dump_config_;

  StringList included_categories_;
  StringList disabled_categories_;
  StringList excluded_categories_;
  StringList synthetic_delays_;
  EventFilters event_filters_;
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_TRACE_CONFIG_H_

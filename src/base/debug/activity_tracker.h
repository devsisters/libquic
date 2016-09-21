// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Activity tracking provides a low-overhead method of collecting information
// about the state of the application for analysis both while it is running
// and after it has terminated unexpectedly. Its primary purpose is to help
// locate reasons the browser becomes unresponsive by providing insight into
// what all the various threads and processes are (or were) doing.

#ifndef BASE_DEBUG_ACTIVITY_TRACKER_H_
#define BASE_DEBUG_ACTIVITY_TRACKER_H_

// std::atomic is undesired due to performance issues when used as global
// variables. There are no such instances here. This module uses the
// PersistentMemoryAllocator which also uses std::atomic and is written
// by the same author.
#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "base/base_export.h"
#include "base/location.h"
#include "base/metrics/persistent_memory_allocator.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_checker.h"
#include "base/threading/thread_local_storage.h"

namespace base {

struct PendingTask;

class FilePath;
class Lock;
class MemoryMappedFile;
class PlatformThreadHandle;
class Process;
class WaitableEvent;

namespace debug {

class ThreadActivityTracker;


enum : int {
  // The maximum number of call-stack addresses stored per activity. This
  // cannot be changed without also changing the version number of the
  // structure. See kTypeIdActivityTracker in GlobalActivityTracker.
  kActivityCallStackSize = 10,
};

// The data associated with an activity is dependent upon the activity type.
// This union defines all of the various fields. All fields must be explicitly
// sized types to ensure no interoperability problems between 32-bit and
// 64-bit systems.
union ActivityData {
  // Generic activities don't have any defined structure.
  struct {
    uint32_t id;   // An arbitrary identifier used for association.
    int32_t info;  // An arbitrary value used for information purposes.
  } generic;
  struct {
    uint64_t sequence_id;  // The sequence identifier of the posted task.
  } task;
  struct {
    uint64_t lock_address;  // The memory address of the lock object.
  } lock;
  struct {
    uint64_t event_address;  // The memory address of the event object.
  } event;
  struct {
    int64_t thread_id;  // A unique identifier for a thread within a process.
  } thread;
  struct {
    int64_t process_id;  // A unique identifier for a process.
  } process;

  // These methods create an ActivityData object from the appropriate
  // parameters. Objects of this type should always be created this way to
  // ensure that no fields remain unpopulated should the set of recorded
  // fields change. They're defined inline where practical because they
  // reduce to loading a small local structure with a few values, roughly
  // the same as loading all those values into parameters.

  static ActivityData ForGeneric(uint32_t id, int32_t info) {
    ActivityData data;
    data.generic.id = id;
    data.generic.info = info;
    return data;
  }

  static ActivityData ForTask(uint64_t sequence) {
    ActivityData data;
    data.task.sequence_id = sequence;
    return data;
  }

  static ActivityData ForLock(const void* lock) {
    ActivityData data;
    data.lock.lock_address = reinterpret_cast<uintptr_t>(lock);
    return data;
  }

  static ActivityData ForEvent(const void* event) {
    ActivityData data;
    data.event.event_address = reinterpret_cast<uintptr_t>(event);
    return data;
  }

  static ActivityData ForThread(const PlatformThreadHandle& handle);
  static ActivityData ForThread(const int64_t id) {
    ActivityData data;
    data.thread.thread_id = id;
    return data;
  }

  static ActivityData ForProcess(const int64_t id) {
    ActivityData data;
    data.process.process_id = id;
    return data;
  }
};

// A "null" activity-data that can be passed to indicate "do not change".
extern const ActivityData kNullActivityData;

// This structure is the full contents recorded for every activity pushed
// onto the stack. The |activity_type| indicates what is actually stored in
// the |data| field. All fields must be explicitly sized types to ensure no
// interoperability problems between 32-bit and 64-bit systems.
struct Activity {
  // The type of an activity on the stack. Activities are broken into
  // categories with the category ID taking the top 4 bits and the lower
  // bits representing an action within that category. This combination
  // makes it easy to "switch" based on the type during analysis.
  enum Type : uint8_t {
    // This "null" constant is used to indicate "do not change" in calls.
    ACT_NULL = 0,

    // Task activities involve callbacks posted to a thread or thread-pool
    // using the PostTask() method or any of its friends.
    ACT_TASK = 1 << 4,
    ACT_TASK_RUN = ACT_TASK,

    // Lock activities involve the acquisition of "mutex" locks.
    ACT_LOCK = 2 << 4,
    ACT_LOCK_ACQUIRE = ACT_LOCK,
    ACT_LOCK_RELEASE,

    // Event activities involve operations on a WaitableEvent.
    ACT_EVENT = 3 << 4,
    ACT_EVENT_WAIT = ACT_EVENT,
    ACT_EVENT_SIGNAL,

    // Thread activities involve the life management of threads.
    ACT_THREAD = 4 << 4,
    ACT_THREAD_START = ACT_THREAD,
    ACT_THREAD_JOIN,

    // Process activities involve the life management of processes.
    ACT_PROCESS = 5 << 4,
    ACT_PROCESS_START = ACT_PROCESS,
    ACT_PROCESS_WAIT,

    // Generic activities are user defined and can be anything.
    ACT_GENERIC = 15 << 4,

    // These constants can be used to separate the category and action from
    // a combined activity type.
    ACT_CATEGORY_MASK = 0xF << 4,
    ACT_ACTION_MASK = 0xF
  };

  // Internal representation of time. During collection, this is in "ticks"
  // but when returned in a snapshot, it is "wall time".
  int64_t time_internal;

  // The address that is the origin of the activity if it not obvious from
  // the call stack. This is useful for things like tasks that are posted
  // from a completely different thread though most activities will leave
  // it null.
  uint64_t origin_address;

  // Array of program-counters that make up the top of the call stack.
  // Despite the fixed size, this list is always null-terminated. Entries
  // after the terminator have no meaning and may or may not also be null.
  // The list will be completely empty if call-stack collection is not
  // enabled.
  uint64_t call_stack[kActivityCallStackSize];

  // The (enumerated) type of the activity. This defines what fields of the
  // |data| record are valid.
  uint8_t activity_type;

  // Padding to ensure that the next member begins on a 64-bit boundary
  // even on 32-bit builds which ensures inter-operability between CPU
  // architectures. New fields can be taken from this space.
  uint8_t padding[7];

  // Information specific to the |activity_type|.
  ActivityData data;

  static void FillFrom(Activity* activity,
                       const void* origin,
                       Type type,
                       const ActivityData& data);
};

// This structure holds a copy of all the internal data at the moment the
// "snapshot" operation is done. It is disconnected from the live tracker
// so that continued operation of the thread will not cause changes here.
struct BASE_EXPORT ActivitySnapshot {
  // Explicit constructor/destructor are needed because of complex types
  // with non-trivial default constructors and destructors.
  ActivitySnapshot();
  ~ActivitySnapshot();

  // The name of the thread as set when it was created. The name may be
  // truncated due to internal length limitations.
  std::string thread_name;

  // The process and thread IDs. These values have no meaning other than
  // they uniquely identify a running process and a running thread within
  // that process.  Thread-IDs can be re-used across different processes
  // and both can be re-used after the process/thread exits.
  int64_t process_id = 0;
  int64_t thread_id = 0;

  // The current stack of activities that are underway for this thread. It
  // is limited in its maximum size with later entries being left off.
  std::vector<Activity> activity_stack;

  // The current total depth of the activity stack, including those later
  // entries not recorded in the |activity_stack| vector.
  uint32_t activity_stack_depth = 0;
};


// This class manages tracking a stack of activities for a single thread in
// a persistent manner, implementing a bounded-size stack in a fixed-size
// memory allocation. In order to support an operational mode where another
// thread is analyzing this data in real-time, atomic operations are used
// where necessary to guarantee a consistent view from the outside.
//
// This class is not generally used directly but instead managed by the
// GlobalActivityTracker instance and updated using Scoped*Activity local
// objects.
class BASE_EXPORT ThreadActivityTracker {
 public:
  // This is the base class for having the compiler manage an activity on the
  // tracker's stack. It does nothing but call methods on the passed |tracker|
  // if it is not null, making it safe (and cheap) to create these objects
  // even if activity tracking is not enabled.
  class BASE_EXPORT ScopedActivity {
   public:
    ScopedActivity(ThreadActivityTracker* tracker,
                   const void* origin,
                   Activity::Type type,
                   const ActivityData& data)
        : tracker_(tracker) {
      if (tracker_)
        tracker_->PushActivity(origin, type, data);
    }

    ~ScopedActivity() {
      if (tracker_)
        tracker_->PopActivity();
    }

    void ChangeTypeAndData(Activity::Type type, const ActivityData& data) {
      if (tracker_)
        tracker_->ChangeActivity(type, data);
    }

   private:
    // The thread tracker to which this object reports. It can be null if
    // activity tracking is not (yet) enabled.
    ThreadActivityTracker* const tracker_;

    DISALLOW_COPY_AND_ASSIGN(ScopedActivity);
  };

  // A ThreadActivityTracker runs on top of memory that is managed externally.
  // It must be large enough for the internal header and a few Activity
  // blocks. See SizeForStackDepth().
  ThreadActivityTracker(void* base, size_t size);
  virtual ~ThreadActivityTracker();

  // Indicates that an activity has started from a given |origin| address in
  // the code, though it can be null if the creator's address is not known.
  // The |type| and |data| describe the activity.
  void PushActivity(const void* origin,
                    Activity::Type type,
                    const ActivityData& data);

  // Changes the activity |type| and |data| of the top-most entry on the stack.
  // This is useful if the information has changed and it is desireable to
  // track that change without creating a new stack entry. If the type is
  // ACT_NULL or the data is kNullActivityData then that value will remain
  // unchanged. The type, if changed, must remain in the same category.
  // Changing both is not atomic so a snapshot operation could occur between
  // the update of |type| and |data| or between update of |data| fields.
  void ChangeActivity(Activity::Type type, const ActivityData& data);

  // Indicates that an activity has completed.
  void PopActivity();

  // Returns whether the current data is valid or not. It is not valid if
  // corruption has been detected in the header or other data structures.
  bool IsValid() const;

  // Gets a copy of the tracker contents for analysis. Returns false if a
  // snapshot was not possible, perhaps because the data is not valid; the
  // contents of |output_snapshot| are undefined in that case. The current
  // implementation does not support concurrent snapshot operations.
  bool Snapshot(ActivitySnapshot* output_snapshot) const;

  // Calculates the memory size required for a given stack depth, including
  // the internal header structure for the stack.
  static size_t SizeForStackDepth(int stack_depth);

 private:
  friend class ActivityTrackerTest;

  // This structure contains all the common information about the thread so
  // it doesn't have to be repeated in every entry on the stack. It is defined
  // and used completely within the .cc file.
  struct Header;

  Header* const header_;        // Pointer to the Header structure.
  Activity* const stack_;       // The stack of activities.
  const uint32_t stack_slots_;  // The total number of stack slots.

  bool valid_ = false;          // Tracks whether the data is valid or not.

  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(ThreadActivityTracker);
};


// The global tracker manages all the individual thread trackers. Memory for
// the thread trackers is taken from a PersistentMemoryAllocator which allows
// for the data to be analyzed by a parallel process or even post-mortem.
class BASE_EXPORT GlobalActivityTracker {
  template <typename T>
  class ThreadSafeStack {
   public:
    ThreadSafeStack(size_t size)
        : size_(size), values_(new T[size]), used_(0) {}
    ~ThreadSafeStack() {}

    size_t size() { return size_; }
    size_t used() {
      base::AutoLock autolock(lock_);
      return used_;
    }

    bool push(T value) {
      base::AutoLock autolock(lock_);
      if (used_ == size_)
        return false;
      values_[used_++] = value;
      return true;
    }

    bool pop(T* out_value) {
      base::AutoLock autolock(lock_);
      if (used_ == 0)
        return false;
      *out_value = values_[--used_];
      return true;
    }

   private:
    const size_t size_;

    std::unique_ptr<T[]> values_;
    size_t used_;
    base::Lock lock_;

   private:
    DISALLOW_COPY_AND_ASSIGN(ThreadSafeStack);
  };

 public:
  // Type identifiers used when storing in persistent memory so they can be
  // identified during extraction; the first 4 bytes of the SHA1 of the name
  // is used as a unique integer. A "version number" is added to the base
  // so that, if the structure of that object changes, stored older versions
  // will be safely ignored. These are public so that an external process
  // can recognize records of this type within an allocator.
  enum : uint32_t {
    kTypeIdActivityTracker     = 0x5D7381AF + 1,  // SHA1(ActivityTracker) v1
    kTypeIdActivityTrackerFree = 0x3F0272FB + 1,  // SHA1(ActivityTrackerFree)
  };

  // This is a thin wrapper around the thread-tracker's ScopedActivity that
  // accesses the global tracker to provide some of the information, notably
  // which thread-tracker to use. It is safe to create even if activity
  // tracking is not enabled.
  class BASE_EXPORT ScopedThreadActivity
      : public ThreadActivityTracker::ScopedActivity {
   public:
    ScopedThreadActivity(const void* origin,
                         Activity::Type type,
                         const ActivityData& data,
                         bool lock_allowed)
        : ThreadActivityTracker::ScopedActivity(
              GetOrCreateTracker(lock_allowed),
              origin,
              type,
              data) {}

   private:
    // Gets (or creates) a tracker for the current thread. If locking is not
    // allowed (because a lock is being tracked which would cause recursion)
    // then the attempt to create one if none found will be skipped. Once
    // the tracker for this thread has been created for other reasons, locks
    // will be tracked. The thread-tracker uses locks.
    static ThreadActivityTracker* GetOrCreateTracker(bool lock_allowed) {
      GlobalActivityTracker* global_tracker = Get();
      if (!global_tracker)
        return nullptr;
      if (lock_allowed)
        return global_tracker->GetOrCreateTrackerForCurrentThread();
      else
        return global_tracker->GetTrackerForCurrentThread();
    }

    DISALLOW_COPY_AND_ASSIGN(ScopedThreadActivity);
  };

  ~GlobalActivityTracker();

  // Creates a global tracker using a given persistent-memory |allocator| and
  // providing the given |stack_depth| to each thread tracker it manages. The
  // created object is activated so tracking will begin immediately upon return.
  static void CreateWithAllocator(
      std::unique_ptr<PersistentMemoryAllocator> allocator,
      int stack_depth);

#if !defined(OS_NACL)
  // Like above but internally creates an allocator around a disk file with
  // the specified |size| at the given |file_path|. Any existing file will be
  // overwritten. The |id| and |name| are arbitrary and stored in the allocator
  // for reference by whatever process reads it.
  static void CreateWithFile(const FilePath& file_path,
                             size_t size,
                             uint64_t id,
                             StringPiece name,
                             int stack_depth);
#endif  // !defined(OS_NACL)

  // Like above but internally creates an allocator using local heap memory of
  // the specified size. This is used primarily for unit tests.
  static void CreateWithLocalMemory(size_t size,
                                    uint64_t id,
                                    StringPiece name,
                                    int stack_depth);

  // Gets the global activity-tracker or null if none exists.
  static GlobalActivityTracker* Get() { return g_tracker_; }

  // Gets the persistent-memory-allocator in which data is stored. Callers
  // can store additional records here to pass more information to the
  // analysis process.
  PersistentMemoryAllocator* allocator() { return allocator_.get(); }

  // Gets the thread's activity-tracker if it exists. This is inline for
  // performance reasons and it uses thread-local-storage (TLS) so that there
  // is no significant lookup time required to find the one for the calling
  // thread. Ownership remains with the global tracker.
  ThreadActivityTracker* GetTrackerForCurrentThread() {
    return reinterpret_cast<ThreadActivityTracker*>(this_thread_tracker_.Get());
  }

  // Gets the thread's activity-tracker or creates one if none exists. This
  // is inline for performance reasons. Ownership remains with the global
  // tracker.
  ThreadActivityTracker* GetOrCreateTrackerForCurrentThread() {
    ThreadActivityTracker* tracker = GetTrackerForCurrentThread();
    if (tracker)
      return tracker;
    return CreateTrackerForCurrentThread();
  }

  // Creates an activity-tracker for the current thread.
  ThreadActivityTracker* CreateTrackerForCurrentThread();

  // Releases the activity-tracker for the current thread (for testing only).
  void ReleaseTrackerForCurrentThreadForTesting();

 private:
  friend class ActivityTrackerTest;

  enum : int {
    // The maximum number of threads that can be tracked within a process. If
    // more than this number run concurrently, tracking of new ones may cease.
    kMaxThreadCount = 100,
  };

  // A thin wrapper around the main thread-tracker that keeps additional
  // information that the global tracker needs to handle joined threads.
  class ManagedActivityTracker : public ThreadActivityTracker {
   public:
    ManagedActivityTracker(PersistentMemoryAllocator::Reference mem_reference,
                           void* base,
                           size_t size);
    ~ManagedActivityTracker() override;

    // The reference into persistent memory from which the thread-tracker's
    // memory was created.
    const PersistentMemoryAllocator::Reference mem_reference_;

    // The physical address used for the thread-tracker's memory.
    void* const mem_base_;

   private:
    DISALLOW_COPY_AND_ASSIGN(ManagedActivityTracker);
  };

  // Creates a global tracker using a given persistent-memory |allocator| and
  // providing the given |stack_depth| to each thread tracker it manages. The
  // created object is activated so tracking has already started upon return.
  GlobalActivityTracker(std::unique_ptr<PersistentMemoryAllocator> allocator,
                        int stack_depth);

  // Returns the memory used by an activity-tracker managed by this class.
  // It is called during the destruction of a ManagedActivityTracker object.
  void ReturnTrackerMemory(ManagedActivityTracker* tracker);

  // Releases the activity-tracker associcated with thread. It is called
  // automatically when a thread is joined and thus there is nothing more to
  // be tracked. |value| is a pointer to a ManagedActivityTracker.
  static void OnTLSDestroy(void* value);

  // The persistent-memory allocator from which the memory for all trackers
  // is taken.
  std::unique_ptr<PersistentMemoryAllocator> allocator_;

  // The size (in bytes) of memory required by a ThreadActivityTracker to
  // provide the stack-depth requested during construction.
  const size_t stack_memory_size_;

  // The activity tracker for the currently executing thread.
  base::ThreadLocalStorage::Slot this_thread_tracker_;

  // The number of thread trackers currently active.
  std::atomic<int> thread_tracker_count_;

  // A cache of thread-tracker memories that have been previously freed and
  // thus can be re-used instead of allocating new ones.
  ThreadSafeStack<PersistentMemoryAllocator::Reference> available_memories_;

  // The active global activity tracker.
  static GlobalActivityTracker* g_tracker_;

  DISALLOW_COPY_AND_ASSIGN(GlobalActivityTracker);
};


// Record entry in to and out of an arbitrary block of code.
class BASE_EXPORT ScopedActivity
    : public GlobalActivityTracker::ScopedThreadActivity {
 public:
  // Track activity at the specified FROM_HERE location for an arbitrary
  // 4-bit |action|, an arbitrary 32-bit |id|, and 32-bits of arbitrary
  // |info|. None of these values affect operation; they're all purely
  // for association and analysis. To have unique identifiers across a
  // diverse code-base, create the number by taking the first 8 characters
  // of the hash of the activity being tracked.
  //
  // For example:
  //   Tracking method: void MayNeverExit(uint32_t foo) {...}
  //   echo -n "MayNeverExit" | sha1sum   =>   e44873ccab21e2b71270da24aa1...
  //
  //   void MayNeverExit(int32_t foo) {
  //     base::debug::ScopedActivity track_me(FROM_HERE, 0, 0xE44873CC, foo);
  //     ...
  //   }
  ScopedActivity(const tracked_objects::Location& location,
                 uint8_t action,
                 uint32_t id,
                 int32_t info);

  // Because this is inline, the FROM_HERE macro will resolve the current
  // program-counter as the location in the calling code.
  ScopedActivity() : ScopedActivity(FROM_HERE, 0, 0, 0) {}

  // Changes the |action| and/or |info| of this activity on the stack. This
  // is useful for tracking progress through a function, updating the action
  // to indicate "milestones" in the block (max 16 milestones: 0-15) or the
  // info to reflect other changes. Changing both is not atomic so a snapshot
  // operation could occur between the update of |action| and |info|.
  void ChangeAction(uint8_t action);
  void ChangeInfo(int32_t info);
  void ChangeActionAndInfo(uint8_t action, int32_t info);

 private:
  // A copy of the ID code so it doesn't have to be passed by the caller when
  // changing the |info| field.
  uint32_t id_;

  DISALLOW_COPY_AND_ASSIGN(ScopedActivity);
};


// These "scoped" classes provide easy tracking of various blocking actions.

class BASE_EXPORT ScopedTaskRunActivity
    : public GlobalActivityTracker::ScopedThreadActivity {
 public:
  explicit ScopedTaskRunActivity(const base::PendingTask& task);
 private:
  DISALLOW_COPY_AND_ASSIGN(ScopedTaskRunActivity);
};

class BASE_EXPORT ScopedLockAcquireActivity
    : public GlobalActivityTracker::ScopedThreadActivity {
 public:
  explicit ScopedLockAcquireActivity(const base::internal::LockImpl* lock);
 private:
  DISALLOW_COPY_AND_ASSIGN(ScopedLockAcquireActivity);
};

class BASE_EXPORT ScopedEventWaitActivity
    : public GlobalActivityTracker::ScopedThreadActivity {
 public:
  explicit ScopedEventWaitActivity(const base::WaitableEvent* event);
 private:
  DISALLOW_COPY_AND_ASSIGN(ScopedEventWaitActivity);
};

class BASE_EXPORT ScopedThreadJoinActivity
    : public GlobalActivityTracker::ScopedThreadActivity {
 public:
  explicit ScopedThreadJoinActivity(const base::PlatformThreadHandle* thread);
 private:
  DISALLOW_COPY_AND_ASSIGN(ScopedThreadJoinActivity);
};

// Some systems don't have base::Process
#if !defined(OS_NACL) && !defined(OS_IOS)
class BASE_EXPORT ScopedProcessWaitActivity
    : public GlobalActivityTracker::ScopedThreadActivity {
 public:
  explicit ScopedProcessWaitActivity(const base::Process* process);
 private:
  DISALLOW_COPY_AND_ASSIGN(ScopedProcessWaitActivity);
};
#endif

}  // namespace debug
}  // namespace base

#endif  // BASE_DEBUG_ACTIVITY_TRACKER_H_

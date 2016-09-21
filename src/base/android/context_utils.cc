// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/context_utils.h"

#include <jni.h>

#include "base/android/scoped_java_ref.h"
#include "base/lazy_instance.h"
#include "jni/ContextUtils_jni.h"

using base::android::JavaRef;

namespace base {
namespace android {

namespace {

// Leak the global app context, as it is used from a non-joinable worker thread
// that may still be running at shutdown. There is no harm in doing this.
base::LazyInstance<base::android::ScopedJavaGlobalRef<jobject>>::Leaky
    g_application_context = LAZY_INSTANCE_INITIALIZER;

void SetNativeApplicationContext(JNIEnv* env, const JavaRef<jobject>& context) {
  if (env->IsSameObject(g_application_context.Get().obj(), context.obj())) {
    // It's safe to set the context more than once if it's the same context.
    return;
  }
  DCHECK(g_application_context.Get().is_null());
  g_application_context.Get().Reset(context);
}

}  // namespace

const JavaRef<jobject>& GetApplicationContext() {
  DCHECK(!g_application_context.Get().is_null());
  return g_application_context.Get();
}

static void InitNativeSideApplicationContext(
    JNIEnv* env,
    const JavaParamRef<jclass>& clazz,
    const JavaParamRef<jobject>& context) {
  SetNativeApplicationContext(env, context);
}

bool RegisterContextUtils(JNIEnv* env) {
  return RegisterNativesImpl(env);
}

}  // namespace android
}  // namespace base

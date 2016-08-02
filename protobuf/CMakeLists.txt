cmake_minimum_required (VERSION 2.8.10)

project (libprotobuf)

include_directories(../src/third_party/protobuf/src ../src/third_party/protobuf/)

if (NOT ANDROID)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -DHAVE_PTHREAD")
else ()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_PTHREAD")
endif()

add_library(
	protobuf
	STATIC

	../src/third_party/protobuf/src/google/protobuf/arena.cc
	../src/third_party/protobuf/src/google/protobuf/arena.h
	../src/third_party/protobuf/src/google/protobuf/arenastring.cc
	../src/third_party/protobuf/src/google/protobuf/arenastring.h
	../src/third_party/protobuf/src/google/protobuf/extension_set.cc
	../src/third_party/protobuf/src/google/protobuf/extension_set.h
	../src/third_party/protobuf/src/google/protobuf/generated_message_util.cc
	../src/third_party/protobuf/src/google/protobuf/generated_message_util.h
	../src/third_party/protobuf/src/google/protobuf/io/coded_stream.cc
	../src/third_party/protobuf/src/google/protobuf/io/coded_stream.h
	../src/third_party/protobuf/src/google/protobuf/io/coded_stream_inl.h
	../src/third_party/protobuf/src/google/protobuf/io/zero_copy_stream.cc
	../src/third_party/protobuf/src/google/protobuf/io/zero_copy_stream.h
	../src/third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl_lite.cc
	../src/third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl_lite.h
	../src/third_party/protobuf/src/google/protobuf/message_lite.cc
	../src/third_party/protobuf/src/google/protobuf/message_lite.h
	../src/third_party/protobuf/src/google/protobuf/repeated_field.cc
	../src/third_party/protobuf/src/google/protobuf/repeated_field.h
	../src/third_party/protobuf/src/google/protobuf/stubs/atomicops.h
	../src/third_party/protobuf/src/google/protobuf/stubs/atomicops_internals_arm_gcc.h
	../src/third_party/protobuf/src/google/protobuf/stubs/atomicops_internals_atomicword_compat.h
	../src/third_party/protobuf/src/google/protobuf/stubs/atomicops_internals_macosx.h
	../src/third_party/protobuf/src/google/protobuf/stubs/atomicops_internals_mips_gcc.h
	../src/third_party/protobuf/src/google/protobuf/stubs/atomicops_internals_x86_gcc.cc
	../src/third_party/protobuf/src/google/protobuf/stubs/atomicops_internals_x86_gcc.h
	../src/third_party/protobuf/src/google/protobuf/stubs/atomicops_internals_x86_msvc.cc
	../src/third_party/protobuf/src/google/protobuf/stubs/atomicops_internals_x86_msvc.h
	../src/third_party/protobuf/src/google/protobuf/stubs/common.cc
	../src/third_party/protobuf/src/google/protobuf/stubs/common.h
	../src/third_party/protobuf/src/google/protobuf/stubs/structurally_valid.cc
	../src/third_party/protobuf/src/google/protobuf/stubs/common.h
	../src/third_party/protobuf/src/google/protobuf/stubs/hash.h
	../src/third_party/protobuf/src/google/protobuf/stubs/map_util.h
	../src/third_party/protobuf/src/google/protobuf/stubs/once.cc
	../src/third_party/protobuf/src/google/protobuf/stubs/once.h
	../src/third_party/protobuf/src/google/protobuf/stubs/status.cc
	../src/third_party/protobuf/src/google/protobuf/stubs/status.h
	../src/third_party/protobuf/src/google/protobuf/stubs/int128.cc
	../src/third_party/protobuf/src/google/protobuf/stubs/int128.h
	../src/third_party/protobuf/src/google/protobuf/stubs/stringprintf.cc
	../src/third_party/protobuf/src/google/protobuf/stubs/stringprintf.h
	../src/third_party/protobuf/src/google/protobuf/stubs/platform_macros.h
	../src/third_party/protobuf/src/google/protobuf/unknown_field_set.cc
	../src/third_party/protobuf/src/google/protobuf/unknown_field_set.h
	../src/third_party/protobuf/src/google/protobuf/wire_format_lite.cc
	../src/third_party/protobuf/src/google/protobuf/wire_format_lite.h
	../src/third_party/protobuf/src/google/protobuf/wire_format_lite_inl.h
)

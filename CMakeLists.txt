cmake_minimum_required (VERSION 2.8.10)

project (libquic)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	message(STATUS "Setting build type to 'Debug' as none was specified.")
	set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
	# Set the possible values of build type for cmake-gui
	#set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
	#	"MinSizeRel" "RelWithDebInfo")
endif()

set(COMMON_C_FLAGS "${COMMON_C_FLAGS} -Wall -fpic")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_C_FLAGS} -std=gnu++11")
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_DEBUG "-g")

add_definitions(-DUSE_OPENSSL -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS)

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	set(ARCH "amd64")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "amd64")
	set(ARCH "amd64")
#elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "AMD64")
#	# cmake reports AMD64 on Windows, but we might be building for 32-bit.
#	if (CMAKE_CL_64)
#		set(ARCH "amd64")
#	else()
#		set(ARCH "386")
#	endif()
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86")
	set(ARCH "386")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i386")
	set(ARCH "386")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i686")
	set(ARCH "386")
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "^arm.*")
	set(ARCH "arm")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
	set(ARCH "aarch64")
else()
	message(FATAL_ERROR "Unknown processor:" ${CMAKE_SYSTEM_PROCESSOR})
endif()

if (${ARCH} STREQUAL "386" AND APPLE)
	# With CMake 2.8.x, ${CMAKE_SYSTEM_PROCESSOR} evalutes to i386 on OS X,
	# but clang defaults to 64-bit builds on OS X unless otherwise told.
	# Set ARCH to x86_64 so clang and CMake agree. This is fixed in CMake 3.
	set(ARCH "amd64")
endif()

#add_subdirectory(crypto)

include_directories(src src/third_party/modp_b64 boringssl/include src/third_party/protobuf/src)

set(
	NET_SOURCES

	src/net/quic/core/quic_protocol.cc
	src/net/quic/core/quic_packet_generator.cc
	src/net/quic/core/quic_flow_controller.cc
	src/net/quic/core/quic_connection_stats.cc
	src/net/quic/core/quic_data_writer.cc
	src/net/quic/core/quic_data_reader.cc
	src/net/quic/core/quic_session.cc
	src/net/quic/core/quic_spdy_session.cc
	src/net/quic/core/quic_spdy_stream.cc
	src/net/quic/core/iovector.cc
	src/net/quic/core/quic_stream_sequencer.cc
	src/net/quic/core/quic_framer.cc
	src/net/quic/core/quic_sent_packet_manager.cc
	src/net/quic/core/quic_time.cc
	src/net/quic/core/quic_headers_stream.cc
	src/net/quic/core/quic_connection.cc
	src/net/quic/core/quic_types.cc
	src/net/quic/core/quic_received_packet_manager.cc
	src/net/quic/core/quic_write_blocked_list.cc
	src/net/quic/core/quic_crypto_stream.cc
	src/net/quic/core/quic_socket_address_coder.cc
	src/net/quic/core/quic_utils.cc
	src/net/quic/core/quic_header_list.cc
	src/net/quic/core/spdy_utils.cc
	src/net/quic/core/crypto/aead_base_decrypter.cc
	src/net/quic/core/crypto/aead_base_encrypter.cc
	src/net/quic/core/crypto/chacha20_poly1305_decrypter.cc
	src/net/quic/core/crypto/chacha20_poly1305_encrypter.cc
	src/net/quic/core/crypto/aes_128_gcm_12_decrypter.cc
	src/net/quic/core/crypto/aes_128_gcm_12_encrypter.cc
	src/net/quic/core/crypto/p256_key_exchange.cc
	src/net/quic/core/crypto/quic_compressed_certs_cache.cc
	src/net/quic/core/crypto/quic_crypto_server_config.cc
	src/net/quic/core/crypto/crypto_handshake_message.cc
	src/net/quic/core/crypto/cert_compressor.cc
	src/net/quic/core/crypto/crypto_secret_boxer.cc
	src/net/quic/core/crypto/curve25519_key_exchange.cc
	src/net/quic/core/crypto/quic_decrypter.cc
	src/net/quic/core/crypto/null_decrypter.cc
	src/net/quic/core/crypto/crypto_server_config_protobuf.cc
	src/net/quic/core/crypto/scoped_evp_aead_ctx.cc
	src/net/quic/core/crypto/quic_random.cc
	src/net/quic/core/crypto/common_cert_set.cc
	src/net/quic/core/crypto/null_encrypter.cc
	src/net/quic/core/crypto/crypto_framer.cc
	src/net/quic/core/crypto/crypto_handshake.cc
	src/net/quic/core/crypto/channel_id.cc
	src/net/quic/core/crypto/strike_register.cc
	src/net/quic/core/crypto/crypto_utils.cc
	src/net/quic/core/crypto/local_strike_register_client.cc
	src/net/quic/core/crypto/quic_encrypter.cc
	src/net/quic/core/crypto/quic_crypto_client_config.cc
	src/net/quic/core/crypto/proof_source.cc
	src/net/quic/core/quic_buffered_packet_store.cc
	src/net/quic/core/quic_clock.cc
	src/net/quic/core/quic_alarm.cc
	src/net/quic/core/quic_sent_entropy_manager.cc
	src/net/quic/core/quic_multipath_sent_packet_manager.cc
	src/net/quic/core/congestion_control/pacing_sender.cc
	src/net/quic/core/congestion_control/general_loss_algorithm.cc
	src/net/quic/core/congestion_control/send_algorithm_interface.cc
	src/net/quic/core/congestion_control/cubic.cc
	src/net/quic/core/congestion_control/cubic_bytes.cc
	src/net/quic/core/congestion_control/prr_sender.cc
	src/net/quic/core/congestion_control/hybrid_slow_start.cc
	src/net/quic/core/congestion_control/rtt_stats.cc
	src/net/quic/core/congestion_control/tcp_cubic_sender_base.cc
	src/net/quic/core/congestion_control/tcp_cubic_sender_bytes.cc
	src/net/quic/core/congestion_control/tcp_cubic_sender_packets.cc
	src/net/quic/core/quic_config.cc
	src/net/quic/core/quic_crypto_server_stream.cc
	src/net/quic/core/quic_flags.cc
	src/net/quic/core/reliable_quic_stream.cc
	src/net/quic/core/quic_bandwidth.cc
	src/net/quic/core/quic_unacked_packet_map.cc
	src/net/quic/core/quic_packet_creator.cc
	src/net/quic/core/quic_sustained_bandwidth_recorder.cc
	src/net/quic/core/quic_client_session_base.cc
	src/net/quic/core/quic_client_promised_info.cc
	src/net/quic/core/quic_client_push_promise_index.cc
	src/net/quic/core/quic_crypto_client_stream.cc
	src/net/quic/core/quic_server_id.cc
	src/net/quic/core/quic_simple_buffer_allocator.cc
	src/net/quic/core/quic_stream_sequencer_buffer.cc
	src/net/quic/core/quic_server_session_base.cc

	src/net/base/int128.cc
	src/net/base/escape.cc
	src/net/base/net_errors.cc
	src/net/base/ip_address.cc
	src/net/base/ip_endpoint.cc
	src/net/base/host_port_pair.cc
	src/net/base/address_family.cc
	src/net/base/port_util.cc
	src/net/base/url_util.cc
	src/net/base/parse_number.cc
	src/net/base/arena.cc

	src/net/spdy/spdy_frame_reader.cc
	src/net/spdy/spdy_frame_builder.cc
	src/net/spdy/spdy_framer.cc
	src/net/spdy/spdy_header_block.cc
	src/net/spdy/spdy_headers_block_parser.cc
	src/net/spdy/spdy_framer_decoder_adapter.cc
	src/net/spdy/spdy_protocol.cc
	src/net/spdy/spdy_flags.cc
	src/net/spdy/spdy_alt_svc_wire_format.cc
	src/net/spdy/spdy_pinnable_buffer_piece.cc
	src/net/spdy/spdy_prefixed_buffer_reader.cc
	src/net/spdy/hpack/hpack_constants.cc
	src/net/spdy/hpack/hpack_decoder.cc
	src/net/spdy/hpack/hpack_encoder.cc
	src/net/spdy/hpack/hpack_entry.cc
	src/net/spdy/hpack/hpack_header_table.cc
	src/net/spdy/hpack/hpack_huffman_table.cc
	src/net/spdy/hpack/hpack_huffman_decoder.cc
	src/net/spdy/hpack/hpack_input_stream.cc
	src/net/spdy/hpack/hpack_output_stream.cc
	src/net/spdy/hpack/hpack_static_table.cc
)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	set(
		BASE_ARCH_LIBRARIES
	)
	set(
		BASE_ARCH_SOURCES

		src/base/threading/platform_thread_linux.cc
		src/base/threading/platform_thread_internal_posix.cc
		src/base/strings/sys_string_conversions_posix.cc
		src/base/process/process_linux.cc
		src/base/process/internal_linux.cc
		src/base/process/process_handle_linux.cc
		src/base/process/process_metrics_posix.cc
		src/base/process/process_metrics_linux.cc
		src/base/memory/shared_memory_posix.cc
		src/base/sys_info_linux.cc
		src/base/files/file_util.cc
		src/base/files/file_util_posix.cc
		src/base/files/file_enumerator.cc
		src/base/files/file_enumerator_posix.cc
	)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Android")
	set(
		BASE_ARCH_LIBRARIES
	)
	set(
		BASE_ARCH_SOURCES

		src/base/threading/platform_thread_linux.cc
		src/base/threading/platform_thread_internal_posix.cc
		src/base/threading/thread_local_android.cc
		src/base/strings/sys_string_conversions_posix.cc
		src/base/process/process_handle_linux.cc
		src/base/process/process_metrics_linux.cc
		src/base/memory/shared_memory_posix.cc
		#src/base/sys_info_android.cc
	)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
	set(
		BASE_ARCH_LIBRARIES
	)
	set(
		BASE_ARCH_SOURCES

		src/base/threading/platform_thread_freebsd.cc
		src/base/threading/platform_thread_internal_posix.cc
		src/base/strings/sys_string_conversions_posix.cc
		src/base/process/process_handle_freebsd.cc
		src/base/process/process_metrics_posix.cc
		src/base/memory/shared_memory_posix.cc
		src/base/sys_info_freebsd.cc
		src/base/files/file_util.cc
		src/base/files/file_util_posix.cc
		src/base/files/file_enumerator.cc
		src/base/files/file_enumerator_posix.cc
	)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	FIND_LIBRARY(COREFOUNDATION_LIBRARY CoreFoundation)
	FIND_LIBRARY(COCOA_LIBRARY Cocoa)
	FIND_LIBRARY(SECURITY_LIBRARY Security)

	try_compile(CMAKE_SYSTEM_IS_IOS ${CMAKE_CURRENT_BINARY_DIR}/is_ios
		SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/is_ios.c
		OUTPUT_VARIABLE IOS_TEST)

	set(
		BASE_ARCH_LIBRARIES

		${COREFOUNDATION_LIBRARY}
		${COCOA_LIBRARY}
	)

	if (NOT CMAKE_SYSTEM_IS_IOS)
		list(APPEND BASE_ARCH_LIBRARIES ${SECURITY_LIBRARY})
	endif()

	set(
		BASE_ARCH_SOURCES

		src/base/threading/platform_thread_mac.mm
		src/base/strings/sys_string_conversions_mac.mm
		src/base/process/process_handle_mac.cc
		src/base/mac/foundation_util.mm
		src/base/mac/bundle_locations.mm
		src/base/mac/mach_logging.cc
		src/base/mac/scoped_mach_port.cc
		src/base/mac/scoped_mach_vm.cc
		src/base/time/time_mac.cc
		src/base/memory/shared_memory_mac.cc
		src/base/memory/shared_memory_handle_mac.cc
		src/base/sys_info_mac.mm
	)
endif()

set(
	BASE_SOURCES

	${BASE_ARCH_SOURCES}

	src/base/logging.cc
	src/base/posix/safe_strerror.cc
	src/base/memory/weak_ptr.cc
	src/base/memory/singleton.cc
	src/base/memory/ref_counted.cc
	src/base/memory/aligned_memory.cc
	src/base/rand_util_posix.cc
	src/base/sequence_token.cc
	src/base/trace_event/heap_profiler_allocation_context_tracker.cc
	src/base/trace_event/heap_profiler_allocation_context.cc
	src/base/threading/thread_id_name_manager.cc
	src/base/threading/platform_thread_posix.cc
	src/base/threading/thread_restrictions.cc
	src/base/threading/thread_local_storage_posix.cc
	src/base/threading/thread_local_storage.cc
	src/base/threading/thread_collision_warner.cc
	src/base/threading/thread_checker_impl.cc
	src/base/threading/thread_local_posix.cc
	src/base/time/time_posix.cc
	src/base/time/time.cc
	src/base/synchronization/lock.cc
	src/base/synchronization/lock_impl_posix.cc
	src/base/strings/string_piece.cc
	src/base/strings/string_util.cc
	src/base/strings/string_number_conversions.cc
	src/base/strings/string_util_constants.cc
	src/base/strings/stringprintf.cc
	src/base/strings/string_split.cc
	src/base/strings/string16.cc
	src/base/strings/utf_string_conversion_utils.cc
	src/base/strings/utf_string_conversions.cc
	src/base/strings/utf_offset_string_conversions.cc
	src/base/pickle.cc
	src/base/debug/alias.cc
	src/base/debug/stack_trace.cc
	src/base/debug/debugger.cc
	src/base/debug/activity_tracker.cc
	src/base/callback_helpers.cc
	src/base/json/json_string_value_serializer.cc
	src/base/json/json_parser.cc
	src/base/json/string_escape.cc
	src/base/json/json_writer.cc
	src/base/json/json_reader.cc
	src/base/lazy_instance.cc
	src/base/callback_internal.cc
	src/base/base_switches.cc
	src/base/values.cc
	src/base/at_exit.cc
	src/base/process/process_posix.cc
	src/base/process/process_handle_posix.cc
	src/base/bind_helpers.cc
	src/base/vlog.cc
	src/base/location.cc
	src/base/base64.cc
	src/base/md5.cc
	src/base/hash.cc
	src/base/metrics/statistics_recorder.cc
	src/base/metrics/sample_map.cc
	src/base/metrics/sample_vector.cc
	src/base/metrics/histogram_base.cc
	src/base/metrics/histogram.cc
	src/base/metrics/histogram_samples.cc
	src/base/metrics/sparse_histogram.cc
	src/base/metrics/bucket_ranges.cc
	src/base/metrics/metrics_hashes.cc
	src/base/metrics/persistent_memory_allocator.cc
	src/base/metrics/persistent_sample_map.cc
	src/base/metrics/persistent_histogram_allocator.cc
	src/base/rand_util.cc
	src/base/files/file_path_constants.cc
	src/base/files/file_path.cc
	src/base/files/file.cc
	src/base/files/file_posix.cc
	src/base/files/file_tracing.cc
	src/base/files/scoped_file.cc
	src/base/files/memory_mapped_file.cc
	src/base/files/memory_mapped_file_posix.cc
	src/base/third_party/nspr/prtime.cc
	src/base/third_party/dmg_fp/dtoa.cc
	src/base/third_party/dmg_fp/g_fmt.cc
	src/base/third_party/icu/icu_utf.cc
	src/base/timer/elapsed_timer.cc
	src/base/command_line.cc
	src/base/sys_info.cc
	src/base/sys_info_posix.cc

	src/base/third_party/superfasthash/superfasthash.c
)

set(
	CRYPTO_SOURCES

	src/crypto/curve25519.cc
	src/crypto/hkdf.cc
	src/crypto/hmac.cc
	src/crypto/openssl_util.cc
	src/crypto/symmetric_key.cc
	src/crypto/random.cc
	src/crypto/secure_util.cc
	src/crypto/secure_hash.cc
)

set(
	URL_SOURCES

	src/url/url_constants.cc
	src/url/url_canon_etc.cc
	src/url/url_canon_filesystemurl.cc
	src/url/url_canon_fileurl.cc
	src/url/url_canon_host.cc
	src/url/url_canon_internal.cc
	src/url/url_canon_ip.cc
	src/url/url_canon_mailtourl.cc
	src/url/url_canon_path.cc
	src/url/url_canon_pathurl.cc
	src/url/url_canon_query.cc
	src/url/url_canon_relative.cc
	src/url/url_canon_stdstring.cc
	src/url/url_canon_stdurl.cc
	src/url/url_util.cc
	src/url/url_parse_file.cc
	src/url/gurl.cc
	src/url/third_party/mozilla/url_parse.cc
)

set(
	PROTO_SOURCES

	src/net/quic/core/proto/cached_network_parameters.proto
	src/net/quic/core/proto/source_address_token.proto
)

find_package(Protobuf 3)

if(Protobuf_FOUND AND FALSE)  # Turn off protobuf. Use bundled protobuf instead
	set(GENERATE_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

	foreach(FIL ${PROTO_SOURCES})
		get_filename_component(ABS_FIL ${FIL} ABSOLUTE)
		get_filename_component(ABS_PATH ${ABS_FIL} PATH)
		get_filename_component(FIL_WE ${FIL} NAME_WE)
		get_filename_component(DIRC ${FIL} DIRECTORY)

		list(APPEND PROTO_RESULTS "${GENERATE_ROOT}/${DIRC}/${FIL_WE}.pb.cc")
		list(APPEND PROTO_RESULTS "${GENERATE_ROOT}/${DIRC}/${FIL_WE}.pb.h")

		add_custom_command(
			OUTPUT
			"${GENERATE_ROOT}/${DIRC}/${FIL_WE}.pb.cc"
			"${GENERATE_ROOT}/${DIRC}/${FIL_WE}.pb.h"
			COMMAND  ${PROTOBUF_PROTOC_EXECUTABLE}
			ARGS --cpp_out ${GENERATE_ROOT}/${DIRC} -I${ABS_PATH} ${ABS_FIL}
			DEPENDS ${ABS_FIL} ${PROTOBUF_PROTOC_EXECUTABLE}
			VERBATIM )
	endforeach()
else()
	set(
		PROTO_RESULTS

		src/net/quic/core/proto/cached_network_parameters.pb.cc
		src/net/quic/core/proto/source_address_token.pb.cc
	)

	# message("Cannot find protobuf")
endif()

set_source_files_properties(${PROTO_RESUTS} PROPERTIES GENERATED TRUE)

include_directories(${GENERATE_ROOT}/src)

add_library(
	quic
	STATIC

	${PROTO_RESULTS}
	${NET_SOURCES}
	${BASE_SOURCES}
	${CRYPTO_SOURCES}
	${URL_SOURCES}

	src/third_party/modp_b64/modp_b64.cc
	src/third_party/zlib/gzwrite.c
	src/third_party/zlib/crc32.c
	src/third_party/zlib/zutil.c
	src/third_party/zlib/deflate.c
	src/third_party/zlib/simd_stub.c
	src/third_party/zlib/infback.c
	src/third_party/zlib/inffast.c
	src/third_party/zlib/inflate.c
	src/third_party/zlib/inftrees.c
	src/third_party/zlib/compress.c
	src/third_party/zlib/gzclose.c
	src/third_party/zlib/adler32.c
	src/third_party/zlib/gzlib.c
	src/third_party/zlib/trees.c
	src/third_party/zlib/gzread.c
	src/third_party/zlib/uncompr.c
)
target_link_libraries(quic ${BASE_ARCH_LIBRARIES} ssl crypto protobuf)

#add_executable(
#	test_quic_server
#
#	custom/main.cc
#)

# XXX(serialx): Not sure if this is safe, since our CFLAGS contaminate boringssl build
add_subdirectory(boringssl)
add_subdirectory(protobuf)

#target_link_libraries(test_quic_server quic ssl crypto -pthread ${BASE_ARCH_LIBRARIES})

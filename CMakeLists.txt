cmake_minimum_required (VERSION 2.8.10)

project (libquic)

set(COMMON_C_FLAGS "${COMMON_C_FLAGS} -Wall -g -gdwarf-4")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_C_FLAGS} -std=gnu++11")

add_definitions(-DUSE_OPENSSL)

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
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm")
	set(ARCH "arm")
#elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
#	set(ARCH "aarch64")
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

include_directories(src src/third_party/modp_b64 boringssl/include)

set(
	NET_SOURCES

	src/net/quic/quic_protocol.cc
	src/net/quic/quic_packet_generator.cc
	src/net/quic/quic_flow_controller.cc
	src/net/quic/quic_ack_notifier_manager.cc
	src/net/quic/quic_connection_stats.cc
	src/net/quic/quic_fec_group.cc
	src/net/quic/quic_data_writer.cc
	src/net/quic/quic_data_reader.cc
	src/net/quic/quic_session.cc
	src/net/quic/iovector.cc
	src/net/quic/quic_stream_sequencer.cc
	src/net/quic/quic_framer.cc
	src/net/quic/quic_sent_packet_manager.cc
	src/net/quic/quic_time.cc
	src/net/quic/quic_headers_stream.cc
	src/net/quic/quic_connection.cc
	src/net/quic/quic_types.cc
	src/net/quic/quic_received_packet_manager.cc
	src/net/quic/quic_write_blocked_list.cc
	src/net/quic/quic_crypto_stream.cc
	src/net/quic/quic_socket_address_coder.cc
	src/net/quic/quic_utils.cc
	src/net/quic/quic_ack_notifier.cc
	src/net/quic/crypto/quic_crypto_server_config.cc
	src/net/quic/crypto/crypto_handshake_message.cc
	src/net/quic/crypto/p256_key_exchange_openssl.cc
	src/net/quic/crypto/cached_network_parameters.cc
	src/net/quic/crypto/cert_compressor.cc
	src/net/quic/crypto/crypto_secret_boxer.cc
	src/net/quic/crypto/aes_128_gcm_12_encrypter_openssl.cc
	src/net/quic/crypto/curve25519_key_exchange.cc
	src/net/quic/crypto/chacha20_poly1305_encrypter_openssl.cc
	src/net/quic/crypto/chacha20_poly1305_decrypter_openssl.cc
	src/net/quic/crypto/quic_decrypter.cc
	src/net/quic/crypto/channel_id_openssl.cc
	src/net/quic/crypto/null_decrypter.cc
	src/net/quic/crypto/crypto_server_config_protobuf.cc
	src/net/quic/crypto/aead_base_decrypter_openssl.cc
	src/net/quic/crypto/scoped_evp_aead_ctx.cc
	src/net/quic/crypto/quic_random.cc
	src/net/quic/crypto/common_cert_set.cc
	src/net/quic/crypto/null_encrypter.cc
	src/net/quic/crypto/crypto_framer.cc
	src/net/quic/crypto/crypto_handshake.cc
	src/net/quic/crypto/channel_id.cc
	src/net/quic/crypto/source_address_token.cc
	src/net/quic/crypto/strike_register.cc
	src/net/quic/crypto/aead_base_encrypter_openssl.cc
	src/net/quic/crypto/crypto_utils.cc
	src/net/quic/crypto/local_strike_register_client.cc
	src/net/quic/crypto/aes_128_gcm_12_decrypter_openssl.cc
	src/net/quic/crypto/quic_encrypter.cc
	src/net/quic/crypto/quic_crypto_client_config.cc
	src/net/quic/quic_clock.cc
	src/net/quic/quic_data_stream.cc
	src/net/quic/quic_alarm.cc
	src/net/quic/quic_sent_entropy_manager.cc
	src/net/quic/congestion_control/pacing_sender.cc
	src/net/quic/congestion_control/time_loss_algorithm.cc
	src/net/quic/congestion_control/loss_detection_interface.cc
	src/net/quic/congestion_control/receive_algorithm_interface.cc
	src/net/quic/congestion_control/send_algorithm_interface.cc
	src/net/quic/congestion_control/tcp_receiver.cc
	src/net/quic/congestion_control/cubic.cc
	src/net/quic/congestion_control/cube_root.cc
	src/net/quic/congestion_control/tcp_loss_algorithm.cc
	src/net/quic/congestion_control/prr_sender.cc
	src/net/quic/congestion_control/tcp_cubic_sender.cc
	src/net/quic/congestion_control/hybrid_slow_start.cc
	src/net/quic/congestion_control/rtt_stats.cc
	src/net/quic/quic_config.cc
	src/net/quic/quic_crypto_server_stream.cc
	src/net/quic/quic_flags.cc
	src/net/quic/reliable_quic_stream.cc
	src/net/quic/quic_bandwidth.cc
	src/net/quic/quic_unacked_packet_map.cc
	src/net/quic/quic_packet_creator.cc
	src/net/quic/quic_sustained_bandwidth_recorder.cc
	src/net/quic/quic_client_session_base.cc
	src/net/quic/quic_crypto_client_stream.cc
	src/net/quic/quic_server_id.cc

	src/net/base/int128.cc
	src/net/base/io_buffer.cc
	src/net/base/net_util.cc
	src/net/base/net_errors.cc
	src/net/base/ip_endpoint.cc
	src/net/base/host_port_pair.cc

	src/net/spdy/hpack_string_util.cc
	src/net/spdy/hpack_output_stream.cc
	src/net/spdy/hpack_input_stream.cc
	src/net/spdy/spdy_frame_reader.cc
	src/net/spdy/spdy_frame_builder.cc
	src/net/spdy/hpack_decoder.cc
	src/net/spdy/hpack_header_table.cc
	src/net/spdy/hpack_entry.cc
	src/net/spdy/hpack_static_table.cc
	src/net/spdy/hpack_constants.cc
	src/net/spdy/spdy_framer.cc
	src/net/spdy/hpack_encoder.cc
	src/net/spdy/spdy_protocol.cc
	src/net/spdy/hpack_huffman_table.cc
)

set(
	BASE_SOURCES

	src/base/logging.cc
	src/base/memory/weak_ptr.cc
	src/base/memory/singleton.cc
	src/base/memory/ref_counted.cc
	src/base/memory/aligned_memory.cc
	src/base/rand_util_posix.cc
	src/base/threading/thread_id_name_manager.cc
	src/base/threading/platform_thread_posix.cc
	src/base/threading/thread_restrictions.cc
	src/base/threading/thread_local_storage_posix.cc
	src/base/threading/thread_local_storage.cc
	src/base/threading/thread_collision_warner.cc
	src/base/threading/platform_thread_linux.cc
	src/base/threading/thread_local_posix.cc
	src/base/safe_strerror_posix.cc
	src/base/time/time_posix.cc
	src/base/time/time.cc
	src/base/synchronization/waitable_event_posix.cc
	src/base/synchronization/lock.cc
	src/base/synchronization/lock_impl_posix.cc
	src/base/synchronization/condition_variable_posix.cc
	src/base/strings/sys_string_conversions_posix.cc
	src/base/strings/string_piece.cc
	src/base/strings/string_util.cc
	src/base/strings/string_number_conversions.cc
	src/base/strings/string_util_constants.cc
	src/base/strings/stringprintf.cc
	src/base/strings/string_split.cc
	src/base/strings/string16.cc
	src/base/strings/utf_string_conversion_utils.cc
	src/base/strings/utf_string_conversions.cc
	src/base/pickle.cc
	src/base/debug/alias.cc
	src/base/debug/stack_trace.cc
	src/base/debug/debugger.cc
	src/base/callback_helpers.cc
	src/base/atomicops_internals_x86_gcc.cc
	src/base/json/json_string_value_serializer.cc
	src/base/json/json_parser.cc
	src/base/json/string_escape.cc
	src/base/json/json_writer.cc
	src/base/json/json_reader.cc
	src/base/lazy_instance.cc
	src/base/callback_internal.cc
	src/base/base_switches.cc
	src/base/os_compat_nacl.cc
	src/base/values.cc
	src/base/at_exit.cc
	src/base/process/process_handle_posix.cc
	src/base/bind_helpers.cc
	src/base/vlog.cc
	src/base/location.cc
	src/base/base64.cc
	src/base/metrics/statistics_recorder.cc
	src/base/metrics/histogram_base.cc
	src/base/metrics/sample_map.cc
	src/base/metrics/histogram.cc
	src/base/metrics/sample_vector.cc
	src/base/metrics/histogram_samples.cc
	src/base/metrics/bucket_ranges.cc
	src/base/metrics/sparse_histogram.cc
	src/base/rand_util.cc
	src/base/files/file_path_constants.cc
	src/base/files/file_path.cc
	src/base/third_party/nspr/prtime.cc
	src/base/third_party/dmg_fp/dtoa.cc
	src/base/third_party/dmg_fp/g_fmt.cc
	src/base/third_party/icu/icu_utf.cc
	src/base/hash.cc
	src/base/command_line.cc

	src/base/third_party/superfasthash/superfasthash.c
)

set(
	CRYPTO_SOURCES

	src/crypto/curve25519-donna.c
	src/crypto/hkdf.cc
	src/crypto/hmac.cc
	src/crypto/openssl_util.cc
	src/crypto/curve25519.cc
	src/crypto/hmac_openssl.cc
	src/crypto/symmetric_key_openssl.cc
	src/crypto/secure_hash_openssl.cc
	src/crypto/random.cc
	src/crypto/secure_util.cc
)

add_library(
	quic
	STATIC

	${NET_SOURCES}
	${BASE_SOURCES}
	${CRYPTO_SOURCES}

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

add_executable(
	test_quic_server

	custom/main.cc
)

# XXX(serialx): Not sure if this is safe, since our CFLAGS contaminate boringssl build
add_subdirectory(boringssl)

target_link_libraries(test_quic_server quic ssl crypto -pthread)

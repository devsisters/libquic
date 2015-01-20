CC=g++
AR=ar
C=gcc
CFLAGS=-Wall -Isrc -Isrc/third_party/modp_b64 -DUSE_OPENSSL=1 -Iboringssl/include -g -gdwarf-4
CPPFLAGS=--std=gnu++11
LDFLAGS=-pthread -Lboringssl/build/crypto -Lboringssl/build/ssl
LDLIBS=-lssl -lcrypto
CHROMIUM=/home/hodduc/repos/chromium/src
SRCROOT=$(CURDIR)/src
CPP_FILES:=$(wildcard src/*/*.cc) $(wildcard src/*/*/*.cc) $(wildcard src/*/*/*/*.cc)
CPP_BASE_FILES:=$(CPP_FILES:src/%=%)
C_FILES:=$(wildcard src/*/*.c) $(wildcard src/*/*/*.c) $(wildcard src/*/*/*/*.c)
C_BASE_FILES:=$(C_FILES:src/%=%)
OBJ_FILES:=$(addprefix obj/,$(CPP_BASE_FILES:.cc=.o)) $(addprefix obj/,$(C_BASE_FILES:.c=.o)) obj/base/third_party/superfasthash/superfasthash.o obj/crypto/curve25519-donna.o
EXE_FILE=build/exe
LIB_FILE=build/libquic.a

all: init $(OBJ_FILES) $(EXE_FILE) $(LIB_FILE)

$(EXE_FILE): obj/main.o $(LIB_FILE) boringssl/build/.builded
	$(CC) $(LDFLAGS) -o $@ $< $(LIB_FILE) $(LDLIBS)

obj/main.o: custom/main.cc
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(LIB_FILE): $(OBJ_FILES)
	$(AR) rvs $@ $(OBJ_FILES)

boringssl/build/.builded:
	mkdir -p boringssl/build
	cd boringssl/build && cmake -GNinja .. && ninja
	touch boringssl/build/.builded

obj/net/base/net_util_linux.o obj/url/url_util.o obj/base/win/scoped_handle.o obj/net/quic/crypto/common_cert_set_0.o obj/net/quic/crypto/common_cert_set_1.o: custom/empty.cc
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

obj/base/third_party/superfasthash/superfasthash.o: src/base/third_party/superfasthash/superfasthash.c
	mkdir -p $(dir $@)
	$(C) -Wall -Isrc -c -o $@ $<

obj/crypto/curve25519-donna.o: src/crypto/curve25519-donna.c
	mkdir -p $(dir $@)
	$(C) -Wall -Isrc -c -o $@ $<

obj/%.o: src/%.c
	mkdir -p $(dir $@)
	$(C) $(CFLAGS) -c -o $@ $<

obj/%.o: src/%.cc
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

init:
	mkdir -p obj build

sync:
	rm -rf src/* obj/* boringssl/build
	python getdep.py /home/hodduc/repos/chromium/src net/quic/quic_connection.cc \
		--exclude net/base/net_util.h \
		--exclude base/debug/debugger.h \
		--exclude base/sequence_checker.h \
		--exclude base/files/file.h\
		--cmd | bash
	#
	python getdep.py /home/hodduc/repos/chromium/src base/threading/platform_thread_posix.cc \
		--exclude net/base/net_util.h \
		--exclude base/debug/debugger.h \
		--exclude base/sequence_checker.h \
		--exclude base/files/file.h\
		--exclude base/tracked_objects.h \
		--cmd | bash
	
	python getdep.py /home/hodduc/repos/chromium/src base/threading/platform_thread_linux.cc \
		--exclude net/base/net_util.h \
		--exclude base/debug/debugger.h \
		--exclude base/sequence_checker.h \
		--exclude base/files/file.h \
		--exclude base/tracked_objects.h \
		--cmd | bash
	
	python getdep.py /home/hodduc/repos/chromium/src net/quic/quic_session.cc \
		--exclude net/base/net_util.h \
		--exclude base/debug/debugger.h \
		--exclude base/sequence_checker.h \
		--exclude base/files/file.h \
		--exclude base/tracked_objects.h \
		--exclude base/third_party/valgrind/memcheck.h \
		--exclude zconf.h \
		--exclude net/ssl/ssl_info.h \
		--exclude base/metrics/stats_counters.h \
		--exclude url/url_canon.h \
		--exclude net/spdy/spdy_header_block.h \
		--cmd | bash
	
	python getdep.py /home/hodduc/repos/chromium/src net/quic/quic_session.cc \
		--exclude net/base/net_util.h \
		--exclude base/debug/debugger.h \
		--exclude base/sequence_checker.h \
		--exclude base/files/file.h \
		--exclude base/tracked_objects.h \
		--exclude base/third_party/valgrind/memcheck.h \
		--exclude zconf.h \
		--exclude net/ssl/ssl_info.h \
		--exclude base/metrics/stats_counters.h \
		--exclude url/url_canon.h \
		--exclude net/spdy/spdy_header_block.h \
		--cmd | bash
	
	python getdep.py /home/hodduc/repos/chromium/src net/quic/quic_crypto_server_stream.cc \
		--exclude net/base/net_util.h \
		--exclude base/debug/debugger.h \
		--exclude base/sequence_checker.h \
		--exclude base/files/file.h \
		--exclude base/tracked_objects.h \
		--exclude base/third_party/valgrind/memcheck.h \
		--exclude zconf.h \
		--exclude net/ssl/ssl_info.h \
		--exclude base/metrics/stats_counters.h \
		--exclude url/url_canon.h \
		--exclude net/spdy/spdy_header_block.h \
		--exclude modp_b64.h \
		--exclude modp_b64_data.h \
		--exclude base/cpu.h \
		--cmd | bash
		# "third_party/modp_b64.cc" uses relative import. so we should exclude this and add -I option to CFLAGS
	
	cp custom/net_util.h $(SRCROOT)/net/base/net_util.h
	cp custom/net_util.cc $(SRCROOT)/net/base/net_util.cc
	cp custom/debugger.h $(SRCROOT)/base/debug/debugger.h
	cp custom/debugger.cc $(SRCROOT)/base/debug/debugger.cc
	cp custom/sequence_checker.h $(SRCROOT)/base/sequence_checker.h
	cp custom/net_errors.h $(SRCROOT)/net/base/net_errors.h
	cp custom/net_errors.cc $(SRCROOT)/net/base/net_errors.cc
	cp custom/rand_util_posix.cc $(SRCROOT)/base/rand_util_posix.cc
	cp custom/stack_trace.cc $(SRCROOT)/base/debug/stack_trace.cc
	cp custom/platform_thread_posix.cc $(SRCROOT)/base/threading/platform_thread_posix.cc
	cp custom/platform_thread_linux.cc $(SRCROOT)/base/threading/platform_thread_linux.cc
	cp custom/quic_session.h $(SRCROOT)/net/quic/quic_session.h
	cp custom/quic_session.cc $(SRCROOT)/net/quic/quic_session.cc
	cp custom/quic_data_stream.cc $(SRCROOT)/net/quic/quic_data_stream.cc
	cp custom/spdy_framer.h $(SRCROOT)/net/spdy/spdy_framer.h
	cp custom/spdy_framer.cc $(SRCROOT)/net/spdy/spdy_framer.cc
	cp custom/crypto_utils.h $(SRCROOT)/net/quic/crypto/crypto_utils.h
	cp custom/crypto_utils.cc $(SRCROOT)/net/quic/crypto/crypto_utils.cc
	
	rm -f src/base/os_compat_android.*
	
	cp $(CHROMIUM)/base/atomicops_internals_portable.* $(SRCROOT)/base/
	cp $(CHROMIUM)/base/atomicops_internals_x86_gcc.* $(SRCROOT)/base/
	cp $(CHROMIUM)/base/callback_helpers.h $(SRCROOT)/base/
	cp $(CHROMIUM)/base/callback_helpers.cc $(SRCROOT)/base/
	cp $(CHROMIUM)/base/time/time_posix.cc $(SRCROOT)/base/time/
	cp $(CHROMIUM)/base/third_party/dmg_fp/dtoa.cc $(SRCROOT)/base/third_party/dmg_fp/
	cp $(CHROMIUM)/base/third_party/dmg_fp/g_fmt.cc $(SRCROOT)/base/third_party/dmg_fp/
	mkdir -p $(SRCROOT)/base/third_party/superfasthash/
	cp $(CHROMIUM)/base/third_party/superfasthash/superfasthash.c $(SRCROOT)/base/third_party/superfasthash/
	cp $(CHROMIUM)/base/strings/sys_string_conversions_posix.cc $(SRCROOT)/base/strings/
	cp $(CHROMIUM)/base/strings/string_util_constants.cc $(SRCROOT)/base/strings/
	cp $(CHROMIUM)/base/threading/thread_local_storage_posix.cc $(SRCROOT)/base/threading/
	cp $(CHROMIUM)/base/threading/thread_local_posix.cc $(SRCROOT)/base/threading/
	cp $(CHROMIUM)/base/synchronization/lock_impl_posix.cc $(SRCROOT)/base/synchronization/
	cp $(CHROMIUM)/base/synchronization/waitable_event_posix.cc $(SRCROOT)/base/synchronization/
	cp $(CHROMIUM)/base/synchronization/condition_variable.h $(SRCROOT)/base/synchronization/
	cp $(CHROMIUM)/base/synchronization/condition_variable_posix.cc $(SRCROOT)/base/synchronization/
	cp $(CHROMIUM)/base/files/file_path_constants.cc $(SRCROOT)/base/files/
	cp $(CHROMIUM)/base/process/process_handle_posix.cc $(SRCROOT)/base/process/
	cp $(CHROMIUM)/net/base/io_buffer.h $(SRCROOT)/net/base/
	cp $(CHROMIUM)/net/base/io_buffer.cc $(SRCROOT)/net/base/
	cp $(CHROMIUM)/net/quic/crypto/chacha20_poly1305_decrypter.h $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/chacha20_poly1305_decrypter_openssl.cc $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/chacha20_poly1305_encrypter.h $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/chacha20_poly1305_encrypter_openssl.cc $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/aes_128_gcm_12_decrypter.h $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/aes_128_gcm_12_decrypter_openssl.cc $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/aes_128_gcm_12_encrypter.h $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/aes_128_gcm_12_encrypter_openssl.cc $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/aead_base_decrypter.h $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/aead_base_decrypter_openssl.cc $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/aead_base_encrypter.h $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/aead_base_encrypter_openssl.cc $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/p256_key_exchange_openssl.cc $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/net/quic/crypto/channel_id_openssl.cc $(SRCROOT)/net/quic/crypto/
	cp $(CHROMIUM)/crypto/hmac_openssl.cc $(SRCROOT)/crypto/
	cp $(CHROMIUM)/crypto/symmetric_key_openssl.cc $(SRCROOT)/crypto/
	cp $(CHROMIUM)/crypto/openssl_util.h $(SRCROOT)/crypto/
	cp $(CHROMIUM)/crypto/openssl_util.cc $(SRCROOT)/crypto/
	cp $(CHROMIUM)/crypto/secure_hash_openssl.cc $(SRCROOT)/crypto/
	cp $(CHROMIUM)/crypto/curve25519-donna.c $(SRCROOT)/crypto/
	cp $(CHROMIUM)/base/memory/scoped_vector.h $(SRCROOT)/base/memory/
	cp $(CHROMIUM)/third_party/modp_b64/modp_b64_data.h $(SRCROOT)/third_party/modp_b64/
	
	cp -r $(CHROMIUM)/third_party/zlib/*.c $(SRCROOT)/third_party/zlib
	cp -r $(CHROMIUM)/third_party/zlib/*.h $(SRCROOT)/third_party/zlib
	rm $(SRCROOT)/third_party/zlib/crc_folding.c
	rm $(SRCROOT)/third_party/zlib/fill_window_sse.c
	rm $(SRCROOT)/third_party/zlib/x86.c

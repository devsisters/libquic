# This file is used to manage the dependencies to this repo.
#
# If you want to apply upstream chnages,
#  1. Clone & Checkout chromium upstream. Update "chromium_revision" var at DEPS
#  2. Do ./manage.py sync <CHROMIUM_GIT_ROOT>
#     Then, all necessary files will be updated to new one.
#  3. Temporarily commit here. Try build (./buildgo.sh), and you"ll find that you may need a additional patch.
#  4. Do you work, then make a patch by `git diff > new_patch.patch`
#  5. Add patch at DEPS. Amend previous temp commit.
#  6. Commit DEPS, new patch, and source changes

# START #
{
    "chromium_revision": "a5b3eb75b80954fdb346d194419cd47f2ad6b9811",
    "automatic_dependency": [
        {
            "from": "net/quic/quic_connection.cc",
            "exclude": [
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h"
            ]
        },
        {
            "from": "base/threading/platform_thread_posix.cc",
            "exclude": [
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "base/tracked_objects.h"
            ]
        },
        {
            "from": "base/threading/platform_thread_linux.cc",
            "exclude": [
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "base/tracked_objects.h"
            ]
        },
        {
            "from": "net/quic/quic_session.cc",
            "exclude": [
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "base/tracked_objects.h",
                "base/third_party/valgrind/memcheck.h",
                "zconf.h",
                "net/ssl/ssl_info.h",
                "base/metrics/stats_counters.h",
                "url/url_canon.h",
                "net/spdy/spdy_header_block.h"
            ]
        },
        {
            "from": "net/quic/quic_client_session_base.cc",
            "exclude": [
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "base/tracked_objects.h",
                "base/third_party/valgrind/memcheck.h",
                "zconf.h",
                "net/ssl/ssl_info.h",
                "base/metrics/stats_counters.h",
                "url/url_canon.h",
                "net/spdy/spdy_header_block.h",
                "modp_b64.h",
                "modp_b64_data.h",
                "base/cpu.h",
                "net/base/host_port_pair.h",
                "base/profiler/scoped_tracker.h"
            ]
        },
        {
            "from": "net/quic/quic_crypto_client_stream.cc",
            "exclude": [
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "base/tracked_objects.h",
                "base/third_party/valgrind/memcheck.h",
                "zconf.h",
                "net/ssl/ssl_info.h",
                "base/metrics/stats_counters.h",
                "url/url_canon.h",
                "net/spdy/spdy_header_block.h",
                "modp_b64.h",
                "modp_b64_data.h",
                "base/cpu.h",
                "net/base/host_port_pair.h",
                "base/profiler/scoped_tracker.h"
            ]
        },
        {
            "from": "net/quic/quic_crypto_server_stream.cc",
            "exclude": [
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "base/tracked_objects.h",
                "base/third_party/valgrind/memcheck.h",
                "zconf.h",
                "net/ssl/ssl_info.h",
                "base/metrics/stats_counters.h",
                "url/url_canon.h",
                "net/spdy/spdy_header_block.h",
                "modp_b64.h",
                "modp_b64_data.h",
                "base/cpu.h",
                "net/base/host_port_pair.h",
                "base/profiler/scoped_tracker.h"
            ]
        }
    ],
    "manual_dependency": [
        {
            "action": "makedir",
            "target": [
                "base/third_party/superfasthash/"
            ]
        },
        {
            "action": "copy",
            "target": [
                "base/atomicops_internals_portable.*",
                "base/atomicops_internals_x86_gcc.*",
                "base/callback_helpers.h",
                "base/callback_helpers.cc",
                "base/cancelable_callback.h",
                "base/rand_util_posix.cc",
                "base/sequence_checker.h",
                "base/debug/debugger.h",
                "base/debug/debugger.cc",
                "base/time/time_posix.cc",
                "base/third_party/dmg_fp/dtoa.cc",
                "base/third_party/dmg_fp/g_fmt.cc",
                "base/third_party/superfasthash/superfasthash.c",
                "base/strings/sys_string_conversions_posix.cc",
                "base/strings/string_util_constants.cc",
                "base/threading/thread_local_storage_posix.cc",
                "base/threading/thread_local_posix.cc",
                "base/threading/platform_thread_mac.mm",
                "base/synchronization/lock_impl_posix.cc",
                "base/synchronization/waitable_event_posix.cc",
                "base/synchronization/condition_variable.h",
                "base/synchronization/condition_variable_posix.cc",
                "base/files/file_path_constants.cc",
                "base/process/process_handle_posix.cc",
                "net/base/io_buffer.h",
                "net/base/io_buffer.cc",
                "net/base/completion_callback.h",
                "net/base/net_util.h",
                "net/base/net_util.cc",
                "net/base/host_port_pair.h",
                "net/base/host_port_pair.cc",
                "net/quic/crypto/chacha20_poly1305_decrypter.h",
                "net/quic/crypto/chacha20_poly1305_decrypter_openssl.cc",
                "net/quic/crypto/chacha20_poly1305_encrypter.h",
                "net/quic/crypto/chacha20_poly1305_encrypter_openssl.cc",
                "net/quic/crypto/aes_128_gcm_12_decrypter.h",
                "net/quic/crypto/aes_128_gcm_12_decrypter_openssl.cc",
                "net/quic/crypto/aes_128_gcm_12_encrypter.h",
                "net/quic/crypto/aes_128_gcm_12_encrypter_openssl.cc",
                "net/quic/crypto/aead_base_decrypter.h",
                "net/quic/crypto/aead_base_decrypter_openssl.cc",
                "net/quic/crypto/aead_base_encrypter.h",
                "net/quic/crypto/aead_base_encrypter_openssl.cc",
                "net/quic/crypto/p256_key_exchange_openssl.cc",
                "net/quic/crypto/channel_id_openssl.cc",
                "crypto/hmac_openssl.cc",
                "crypto/symmetric_key_openssl.cc",
                "crypto/openssl_util.h",
                "crypto/openssl_util.cc",
                "crypto/secure_hash_openssl.cc",
                "crypto/curve25519-donna.c",
                "base/memory/scoped_vector.h",
                "third_party/modp_b64/modp_b64_data.h",
                "base/mac/mach_logging.cc",
                "base/mac/mach_logging.h",
                "base/mac/scoped_mach_port.cc",
                "base/mac/scoped_mach_port.h",
                "base/scoped_generic.h",
                "base/time/time_mac.cc",
                "third_party/zlib/*.c",
                "third_party/zlib/*.h"
            ]
        },
        {
            "action": "remove",
            "target": [
                "src/base/os_compat_android.*",
                "third_party/zlib/crc_folding.c",
                "third_party/zlib/fill_window_sse.c",
                "third_party/zlib/x86.c"
            ]
        }
    ],
    "patches": [
        "basepatch.patch",
        "patch_remove_scoped_tracker.patch"
    ],
    "custom_files": [
        {"from": "custom/net_util.h", "to": "net/base/net_util.h"},
        {"from": "custom/net_util.cc", "to": "net/base/net_util.cc"},
        {"from": "custom/debugger.h", "to": "base/debug/debugger.h"},
        {"from": "custom/debugger.cc", "to": "base/debug/debugger.cc"}
    ]
}

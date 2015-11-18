# This file is used to manage the dependencies to this repo.
# If you want to apply upstream changes, see README for more details

# START #
{
    "chromium_revision": "ae8b8ce028ee77fb1bd35a83be04d2f176ef440e",
    "automatic_dependency": [
        {
            "from": "net/quic/quic_connection.cc",
            "exclude": [
                "cached_network_parameters.pb.h",
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h"
            ]
        },
        {
            "from": "base/threading/platform_thread_posix.cc",
            "exclude": [
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h"
            ]
        },
        {
            "from": "base/threading/platform_thread_linux.cc",
            "exclude": [
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "base/tracked_objects.h"
            ]
        },
        {
            "from": "net/quic/quic_session.cc",
            "exclude": [
                "cached_network_parameters.pb.h",
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "net/ssl/ssl_info.h",
                "url/url_canon.h",
                "net/spdy/spdy_header_block.h"
            ]
        },
        {
            "from": "net/quic/quic_client_session_base.cc",
            "exclude": [
                "cached_network_parameters.pb.h",
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "base/third_party/valgrind/memcheck.h",
                "zconf.h",
                "net/ssl/ssl_info.h",
                "url/url_canon.h",
                "net/spdy/spdy_header_block.h",
                "base/cpu.h",
                "net/base/host_port_pair.h"
            ]
        },
        {
            "from": "net/quic/quic_crypto_client_stream.cc",
            "exclude": [
                "cached_network_parameters.pb.h",
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "base/third_party/valgrind/memcheck.h",
                "zconf.h",
                "net/ssl/ssl_info.h",
                "url/url_canon.h",
                "net/spdy/spdy_header_block.h",
                "base/cpu.h",
                "net/base/host_port_pair.h"
            ]
        },
        {
            "from": "net/quic/quic_crypto_server_stream.cc",
            "exclude": [
                "cached_network_parameters.pb.h",
                "source_address_token.pb.h",
                "net/base/net_util.h",
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "zconf.h",
                "net/ssl/ssl_info.h",
                "url/url_canon.h",
                "net/spdy/spdy_header_block.h",
                "modp_b64.h",
                "modp_b64_data.h",
                "base/cpu.h"
            ]
        },
        {
            "from": "crypto/nss_util.cc",
            "exclude": [
                "base/debug/debugger.h",
                "base/sequence_checker.h",
                "base/files/file.h",
                "base/tracked_objects.h",
                "base/cpu.h",
                "base/base_paths_android.h",
                "base/base_paths_win.h",
                "base/message_loop/message_loop.h"
            ]
        }
    ],
    "manual_dependency": [
        {
            "action": "makedir",
            "target": [
                "base/third_party/superfasthash/",
                "crypto/third_party/nss/"
            ]
        },
        {
            "action": "copy",
            "target": [
                "LICENSE",
                "AUTHORS",
                "base/atomicops_internals_portable.*",
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
                "net/quic/crypto/chacha20_poly1305_decrypter_nss.cc",
                "net/quic/crypto/chacha20_poly1305_encrypter.h",
                "net/quic/crypto/chacha20_poly1305_encrypter_openssl.cc",
                "net/quic/crypto/chacha20_poly1305_encrypter_nss.cc",
                "net/quic/crypto/aes_128_gcm_12_decrypter.h",
                "net/quic/crypto/aes_128_gcm_12_decrypter_openssl.cc",
                "net/quic/crypto/aes_128_gcm_12_decrypter_nss.cc",
                "net/quic/crypto/aes_128_gcm_12_encrypter.h",
                "net/quic/crypto/aes_128_gcm_12_encrypter_openssl.cc",
                "net/quic/crypto/aes_128_gcm_12_encrypter_nss.cc",
                "net/quic/crypto/aead_base_decrypter.h",
                "net/quic/crypto/aead_base_decrypter_openssl.cc",
                "net/quic/crypto/aead_base_decrypter_nss.cc",
                "net/quic/crypto/aead_base_encrypter.h",
                "net/quic/crypto/aead_base_encrypter_openssl.cc",
                "net/quic/crypto/aead_base_encrypter_nss.cc",
                "net/quic/crypto/p256_key_exchange_openssl.cc",
                "net/quic/crypto/p256_key_exchange_nss.cc",
                "net/quic/crypto/channel_id_openssl.cc",
                "net/quic/crypto/channel_id_nss.cc",
                "crypto/hmac_openssl.cc",
                "crypto/hmac_nss.cc",
                "crypto/symmetric_key_openssl.cc",
                "crypto/symmetric_key_nss.cc",
                "crypto/openssl_util.h",
                "crypto/openssl_util.cc",
                "crypto/nss_util.h",
                "crypto/nss_util_internal.h",
                "crypto/nss_util.cc",
                "crypto/ec_private_key_nss.cc",
                "crypto/secure_hash_openssl.cc",
                "crypto/secure_hash_default.cc",
                "crypto/curve25519-donna.c",
                "crypto/ghash.cc",
                "crypto/ghash.h",
                "base/memory/scoped_vector.h",
                "third_party/modp_b64/modp_b64_data.h",
                "base/mac/mach_logging.cc",
                "base/mac/mach_logging.h",
                "base/mac/scoped_mach_port.cc",
                "base/mac/scoped_mach_port.h",
                "base/scoped_generic.h",
                "base/time/time_mac.cc",
                "third_party/zlib/*.c",
                "third_party/zlib/*.h",
                "crypto/third_party/nss/*.c",
                "crypto/third_party/nss/*.cc",
                "crypto/third_party/nss/*.h"
            ]
        },
        {
            "action": "copydir",
            "target": [
                "third_party/protobuf"
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
        "patch/basepatch.patch"
    ],
    "custom_files": [
        {"from": "custom/net_util.h", "to": "net/base/net_util.h"},
        {"from": "custom/net_util.cc", "to": "net/base/net_util.cc"},
        {"from": "custom/debugger.h", "to": "base/debug/debugger.h"},
        {"from": "custom/debugger.cc", "to": "base/debug/debugger.cc"}
    ]
}

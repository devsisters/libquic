# This file is used to manage the dependencies to this repo.
# If you want to apply upstream changes, see README for more details

# START #
{
    "chromium_revision": "192da0f866b250d8a674a7dd400ff2a5b6a01ac8",
    "automatic_dependency_common_exclude": [
        "base/debug/debugger.h",
        "base/sequence_checker.h",
        "base/files/file.h",
        "base/tracked_objects.h",
        "cached_network_parameters.pb.h",
        "base/feature_list.h",
        "base/metrics/field_trial.h"
    ],
    "automatic_dependency": [
        {
            "from": "base/threading/platform_thread_posix.cc"
        },
        {
            "from": "base/threading/platform_thread_linux.cc"
        },
        {
            "from": "base/threading/platform_thread_freebsd.cc"
        },
        {
            "from": "net/quic/quic_connection.cc",
            "exclude": [
                "net/base/registry_controlled_domains/registry_controlled_domain.h"
            ]
        },
        {
            "from": "net/quic/quic_session.cc",
            "exclude": [
                "net/ssl/ssl_info.h",
                "net/spdy/spdy_header_block.h",
                "net/base/registry_controlled_domains/registry_controlled_domain.h"
            ]
        },
        {
            "from": "net/quic/quic_client_session_base.cc",
            "exclude": [
                "zconf.h",
                "net/ssl/ssl_info.h",
                "net/spdy/spdy_header_block.h",
                "net/base/host_port_pair.h",
                "net/base/registry_controlled_domains/registry_controlled_domain.h"
            ]
        },
        {
            "from": "net/quic/quic_crypto_client_stream.cc",
            "exclude": [
                "zconf.h",
                "net/ssl/ssl_info.h",
                "net/spdy/spdy_header_block.h",
                "net/base/host_port_pair.h",
                "net/base/registry_controlled_domains/registry_controlled_domain.h"
            ]
        },
        {
            "from": "net/quic/quic_crypto_server_stream.cc",
            "exclude": [
                "source_address_token.pb.h",
                "zconf.h",
                "net/ssl/ssl_info.h",
                "net/spdy/spdy_header_block.h",
                "modp_b64.h",
                "modp_b64_data.h",
                "net/base/registry_controlled_domains/registry_controlled_domain.h"
            ]
        },
        {
            "from": "base/strings/sys_string_conversions_mac.mm"
        },
        {
            "from": "net/base/io_buffer.h"
        }
    ],
    "manual_dependency": [
        {
            "action": "makedir",
            "target": [
                "base/third_party/superfasthash/",
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
                "net/base/completion_callback.h",
                "net/base/host_port_pair.h",
                "net/base/host_port_pair.cc",
                "net/quic/quic_simple_buffer_allocator.h",
                "net/quic/quic_simple_buffer_allocator.cc",
                "crypto/hmac_openssl.cc",
                "crypto/symmetric_key_openssl.cc",
                "base/memory/scoped_vector.h",
                "third_party/modp_b64/modp_b64_data.h",
                "base/mac/mach_logging.cc",
                "base/mac/mach_logging.h",
                "base/mac/scoped_mach_port.cc",
                "base/mac/scoped_mach_port.h",
                "base/time/time_mac.cc",
                "base/feature_list.h",
                "third_party/zlib/*.c",
                "third_party/zlib/*.h",
                "url/url_canon_*.cc",
                "url/url_parse_file.cc"
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
        "patch/disable_sequence_checker.patch",
        "patch/net_errors_remove_file_error.patch",
        "patch/quic_session_remove_unused_include.patch",
        "patch/pickle_remove_unused_include.patch",
        "patch/platform_thread_remove_tracked_objects.patch",
        "patch/rand_util_posix.patch",
        "patch/persistent_memory_allocator_disable_sharing.patch",
        "patch/persistent_histogram_allocator_disable_shared_memory.patch",
        "patch/spdy_header_block_remove_unused_callback.patch",
        "patch/url_canon_host_disable_idn_host.patch",
        "patch/url_util_remove_unused_function.patch",
        "patch/disable_stack_trace.patch"
    ],
    "custom_files": [
        {"from": "custom/debugger.h", "to": "base/debug/debugger.h"},
        {"from": "custom/debugger.cc", "to": "base/debug/debugger.cc"},
        {"from": "custom/stubs.cc", "to": "stubs.cc"}
    ]
}

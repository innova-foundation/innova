cmake_minimum_required(VERSION 3.21)
project(Innova VERSION 5.0.0 LANGUAGES C CXX OBJCXX ASM)

# Qt6 build. Homebrew ships Qt6's qmake as a -query stub with no platform
# mkspecs, so the .pro cannot drive a Qt6 build; this is the Qt6 path. The
# source, define and library lists mirror innova-qt.pro.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0" CACHE STRING "")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# The qmake build optimises without NDEBUG, and tor's util_bug.h refuses to
# compile with it defined. Keep the optimisation, drop the define.
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_OBJCXX_FLAGS_RELEASE "-O2")

set(HB /opt/homebrew)
# The umbrella qt formula installs only Find modules under lib/cmake/Qt6; the
# Qt6*Config.cmake packages live in the unlinked qtbase keg, so name it first.
file(GLOB _qtbase_kegs ${HB}/Cellar/qtbase/*)
list(APPEND CMAKE_PREFIX_PATH ${HB}/opt/qtbase ${_qtbase_kegs} ${HB})

set(CMAKE_AUTOMOC ON)
# AUTOUIC is off on purpose: it reads every "ui_*.h" include as one of its own
# outputs, and src/ui_interface.h is a hand-written Innova header. The forms are
# wrapped explicitly below instead.
set(CMAKE_AUTOUIC OFF)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/src/qt/forms)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network Concurrent PrintSupport)

# build.h carries the commit description. Generated at configure so it exists for
# the first compile, and again on every build: generated only at configure, the
# version string froze at whatever commit was checked out when cmake last ran.
# genbuild.sh replaces the file only when its content changes.
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/build)
execute_process(
    COMMAND /bin/sh share/genbuild.sh ${CMAKE_CURRENT_BINARY_DIR}/build/build.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(genbuild ALL
    COMMAND /bin/sh share/genbuild.sh ${CMAKE_CURRENT_BINARY_DIR}/build/build.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/build/build.h
    COMMENT "refreshing build.h")

set(INNOVA_DEFINES
    QT_GUI BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE
    QT_DISABLE_DEPRECATED_BEFORE=0
    USE_IPFS=1 USE_NATIVETOR=1 USE_IPV6=1 USE_LEVELDB
    HAVE_BUILD_INFO MAC_OSX MSG_NOSIGNAL=0 USE_QRCODE)

set(INNOVA_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/json
    ${CMAKE_CURRENT_SOURCE_DIR}/src/qt
    ${CMAKE_CURRENT_SOURCE_DIR}/src/qt/plugins/mrichtexteditor
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ipfs
    ${CMAKE_CURRENT_SOURCE_DIR}/src/minizip
    ${CMAKE_CURRENT_SOURCE_DIR}/src/leveldb/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/leveldb/helpers
    ${CMAKE_CURRENT_BINARY_DIR}/build
    ${HB}/opt/boost/include
    ${HB}/opt/berkeley-db@5/include
    ${HB}/opt/openssl@3/include
    ${HB}/opt/libevent/include
    ${HB}/opt/curl/include
    ${HB}/opt/qrencode/include)

# ---- C sources: tor, secp256k1, minizip, scrypt ----
set(INNOVA_C_SOURCES
    src/minizip/ioapi.c
    src/minizip/unzip.c
    src/tor/src/app/config/config.c
    src/tor/src/app/config/quiet_level.c
    src/tor/src/app/config/resolve_addr.c
    src/tor/src/app/config/statefile.c
    src/tor/src/app/main/main.c
    src/tor/src/app/main/risky_options.c
    src/tor/src/app/main/shutdown.c
    src/tor/src/app/main/subsysmgr.c
    src/tor/src/app/main/subsystem_list.c
    src/tor/src/core/crypto/hs_ntor.c
    src/tor/src/core/crypto/onion_crypto.c
    src/tor/src/core/crypto/onion_fast.c
    src/tor/src/core/crypto/onion_ntor.c
    src/tor/src/core/crypto/onion_ntor_v3.c
    src/tor/src/core/crypto/relay_crypto.c
    src/tor/src/core/crypto/relay_crypto_cgo.c
    src/tor/src/core/crypto/relay_crypto_tor1.c
    src/tor/src/core/mainloop/connection.c
    src/tor/src/core/mainloop/cpuworker.c
    src/tor/src/core/mainloop/mainloop.c
    src/tor/src/core/mainloop/mainloop_pubsub.c
    src/tor/src/core/mainloop/mainloop_sys.c
    src/tor/src/core/mainloop/netstatus.c
    src/tor/src/core/mainloop/periodic.c
    src/tor/src/core/or/address_set.c
    src/tor/src/core/or/channel.c
    src/tor/src/core/or/channelpadding.c
    src/tor/src/core/or/channeltls.c
    src/tor/src/core/or/circuitbuild.c
    src/tor/src/core/or/circuitlist.c
    src/tor/src/core/or/circuitmux.c
    src/tor/src/core/or/circuitmux_ewma.c
    src/tor/src/core/or/circuitpadding.c
    src/tor/src/core/or/circuitpadding_machines.c
    src/tor/src/core/or/circuitstats.c
    src/tor/src/core/or/circuituse.c
    src/tor/src/core/or/command.c
    src/tor/src/core/or/conflux.c
    src/tor/src/core/or/conflux_cell.c
    src/tor/src/core/or/conflux_params.c
    src/tor/src/core/or/conflux_pool.c
    src/tor/src/core/or/conflux_sys.c
    src/tor/src/core/or/conflux_util.c
    src/tor/src/core/or/congestion_control_common.c
    src/tor/src/core/or/congestion_control_flow.c
    src/tor/src/core/or/congestion_control_vegas.c
    src/tor/src/core/or/connection_edge.c
    src/tor/src/core/or/connection_or.c
    src/tor/src/core/or/crypt_path.c
    src/tor/src/core/or/dos.c
    src/tor/src/core/or/dos_config.c
    src/tor/src/core/or/dos_sys.c
    src/tor/src/core/or/extendinfo.c
    src/tor/src/core/or/ocirc_event.c
    src/tor/src/core/or/onion.c
    src/tor/src/core/or/or_periodic.c
    src/tor/src/core/or/or_sys.c
    src/tor/src/core/or/orconn_event.c
    src/tor/src/core/or/policies.c
    src/tor/src/core/or/protover.c
    src/tor/src/core/or/reasons.c
    src/tor/src/core/or/relay.c
    src/tor/src/core/or/relay_msg.c
    src/tor/src/core/or/scheduler.c
    src/tor/src/core/or/scheduler_kist.c
    src/tor/src/core/or/scheduler_vanilla.c
    src/tor/src/core/or/sendme.c
    src/tor/src/core/or/status.c
    src/tor/src/core/or/versions.c
    src/tor/src/core/proto/proto_cell.c
    src/tor/src/core/proto/proto_control0.c
    src/tor/src/core/proto/proto_haproxy.c
    src/tor/src/core/proto/proto_http.c
    src/tor/src/core/proto/proto_socks.c
    src/tor/src/ext/csiphash.c
    src/tor/src/ext/curve25519_donna/curve25519-donna-c64.c
    src/tor/src/ext/ed25519/donna/ed25519_tor.c
    src/tor/src/ext/ed25519/ref10/blinding.c
    src/tor/src/ext/ed25519/ref10/fe_0.c
    src/tor/src/ext/ed25519/ref10/fe_1.c
    src/tor/src/ext/ed25519/ref10/fe_add.c
    src/tor/src/ext/ed25519/ref10/fe_cmov.c
    src/tor/src/ext/ed25519/ref10/fe_copy.c
    src/tor/src/ext/ed25519/ref10/fe_frombytes.c
    src/tor/src/ext/ed25519/ref10/fe_invert.c
    src/tor/src/ext/ed25519/ref10/fe_isnegative.c
    src/tor/src/ext/ed25519/ref10/fe_isnonzero.c
    src/tor/src/ext/ed25519/ref10/fe_mul.c
    src/tor/src/ext/ed25519/ref10/fe_neg.c
    src/tor/src/ext/ed25519/ref10/fe_pow22523.c
    src/tor/src/ext/ed25519/ref10/fe_sq.c
    src/tor/src/ext/ed25519/ref10/fe_sq2.c
    src/tor/src/ext/ed25519/ref10/fe_sub.c
    src/tor/src/ext/ed25519/ref10/fe_tobytes.c
    src/tor/src/ext/ed25519/ref10/ge_add.c
    src/tor/src/ext/ed25519/ref10/ge_double_scalarmult.c
    src/tor/src/ext/ed25519/ref10/ge_frombytes.c
    src/tor/src/ext/ed25519/ref10/ge_madd.c
    src/tor/src/ext/ed25519/ref10/ge_msub.c
    src/tor/src/ext/ed25519/ref10/ge_p1p1_to_p2.c
    src/tor/src/ext/ed25519/ref10/ge_p1p1_to_p3.c
    src/tor/src/ext/ed25519/ref10/ge_p2_0.c
    src/tor/src/ext/ed25519/ref10/ge_p2_dbl.c
    src/tor/src/ext/ed25519/ref10/ge_p3_0.c
    src/tor/src/ext/ed25519/ref10/ge_p3_dbl.c
    src/tor/src/ext/ed25519/ref10/ge_p3_to_cached.c
    src/tor/src/ext/ed25519/ref10/ge_p3_to_p2.c
    src/tor/src/ext/ed25519/ref10/ge_p3_tobytes.c
    src/tor/src/ext/ed25519/ref10/ge_precomp_0.c
    src/tor/src/ext/ed25519/ref10/ge_scalarmult_base.c
    src/tor/src/ext/ed25519/ref10/ge_sub.c
    src/tor/src/ext/ed25519/ref10/ge_tobytes.c
    src/tor/src/ext/ed25519/ref10/keyconv.c
    src/tor/src/ext/ed25519/ref10/keypair.c
    src/tor/src/ext/ed25519/ref10/open.c
    src/tor/src/ext/ed25519/ref10/sc_muladd.c
    src/tor/src/ext/ed25519/ref10/sc_reduce.c
    src/tor/src/ext/ed25519/ref10/sign.c
    src/tor/src/ext/keccak-tiny/keccak-tiny-unrolled.c
    src/tor/src/ext/polyval/polyval.c
    src/tor/src/ext/readpassphrase.c
    src/tor/src/ext/trunnel/trunnel.c
    src/tor/src/feature/api/tor_api.c
    src/tor/src/feature/client/addressmap.c
    src/tor/src/feature/client/bridges.c
    src/tor/src/feature/client/circpathbias.c
    src/tor/src/feature/client/dnsserv.c
    src/tor/src/feature/client/entrynodes.c
    src/tor/src/feature/client/proxymode.c
    src/tor/src/feature/client/transports.c
    src/tor/src/feature/control/btrack.c
    src/tor/src/feature/control/btrack_circuit.c
    src/tor/src/feature/control/btrack_orconn.c
    src/tor/src/feature/control/btrack_orconn_cevent.c
    src/tor/src/feature/control/btrack_orconn_maps.c
    src/tor/src/feature/control/control.c
    src/tor/src/feature/control/control_auth.c
    src/tor/src/feature/control/control_bootstrap.c
    src/tor/src/feature/control/control_cmd.c
    src/tor/src/feature/control/control_events.c
    src/tor/src/feature/control/control_fmt.c
    src/tor/src/feature/control/control_getinfo.c
    src/tor/src/feature/control/control_hs.c
    src/tor/src/feature/control/control_proto.c
    src/tor/src/feature/control/getinfo_geoip.c
    src/tor/src/feature/dirauth/dirauth_stub.c
    src/tor/src/feature/dircache/dircache_stub.c
    src/tor/src/feature/dirclient/dirclient.c
    src/tor/src/feature/dirclient/dirclient_modes.c
    src/tor/src/feature/dirclient/dlstatus.c
    src/tor/src/feature/dircommon/consdiff.c
    src/tor/src/feature/dircommon/directory.c
    src/tor/src/feature/dircommon/fp_pair.c
    src/tor/src/feature/dirparse/authcert_parse.c
    src/tor/src/feature/dirparse/microdesc_parse.c
    src/tor/src/feature/dirparse/ns_parse.c
    src/tor/src/feature/dirparse/parsecommon.c
    src/tor/src/feature/dirparse/policy_parse.c
    src/tor/src/feature/dirparse/routerparse.c
    src/tor/src/feature/dirparse/sigcommon.c
    src/tor/src/feature/dirparse/signing.c
    src/tor/src/feature/dirparse/unparseable.c
    src/tor/src/feature/hibernate/hibernate.c
    src/tor/src/feature/hs/hs_cache.c
    src/tor/src/feature/hs/hs_cell.c
    src/tor/src/feature/hs/hs_circuit.c
    src/tor/src/feature/hs/hs_circuitmap.c
    src/tor/src/feature/hs/hs_client.c
    src/tor/src/feature/hs/hs_common.c
    src/tor/src/feature/hs/hs_config.c
    src/tor/src/feature/hs/hs_control.c
    src/tor/src/feature/hs/hs_descriptor.c
    src/tor/src/feature/hs/hs_dos.c
    src/tor/src/feature/hs/hs_ident.c
    src/tor/src/feature/hs/hs_intropoint.c
    src/tor/src/feature/hs/hs_metrics.c
    src/tor/src/feature/hs/hs_metrics_entry.c
    src/tor/src/feature/hs/hs_ob.c
    src/tor/src/feature/hs/hs_service.c
    src/tor/src/feature/hs/hs_stats.c
    src/tor/src/feature/hs/hs_sys.c
    src/tor/src/feature/hs_common/replaycache.c
    src/tor/src/feature/hs_common/shared_random_client.c
    src/tor/src/feature/keymgt/loadkey.c
    src/tor/src/feature/metrics/metrics.c
    src/tor/src/feature/metrics/metrics_sys.c
    src/tor/src/feature/nodelist/authcert.c
    src/tor/src/feature/nodelist/describe.c
    src/tor/src/feature/nodelist/dirlist.c
    src/tor/src/feature/nodelist/fmt_routerstatus.c
    src/tor/src/feature/nodelist/microdesc.c
    src/tor/src/feature/nodelist/networkstatus.c
    src/tor/src/feature/nodelist/nickname.c
    src/tor/src/feature/nodelist/node_select.c
    src/tor/src/feature/nodelist/nodefamily.c
    src/tor/src/feature/nodelist/nodelist.c
    src/tor/src/feature/nodelist/routerinfo.c
    src/tor/src/feature/nodelist/routerlist.c
    src/tor/src/feature/nodelist/routerset.c
    src/tor/src/feature/nodelist/torcert.c
    src/tor/src/feature/relay/onion_queue.c
    src/tor/src/feature/relay/relay_find_addr.c
    src/tor/src/feature/relay/relay_stub.c
    src/tor/src/feature/relay/router.c
    src/tor/src/feature/rend/rendcommon.c
    src/tor/src/feature/rend/rendmid.c
    src/tor/src/feature/stats/bwhist.c
    src/tor/src/feature/stats/connstats.c
    src/tor/src/feature/stats/geoip_stats.c
    src/tor/src/feature/stats/predict_ports.c
    src/tor/src/feature/stats/rephist.c
    src/tor/src/lib/buf/buffers.c
    src/tor/src/lib/compress/compress.c
    src/tor/src/lib/compress/compress_buf.c
    src/tor/src/lib/compress/compress_lzma.c
    src/tor/src/lib/compress/compress_none.c
    src/tor/src/lib/compress/compress_zlib.c
    src/tor/src/lib/compress/compress_zstd.c
    src/tor/src/lib/confmgt/confmgt.c
    src/tor/src/lib/confmgt/structvar.c
    src/tor/src/lib/confmgt/type_defs.c
    src/tor/src/lib/confmgt/typedvar.c
    src/tor/src/lib/confmgt/unitparse.c
    src/tor/src/lib/container/bloomfilt.c
    src/tor/src/lib/container/map.c
    src/tor/src/lib/container/namemap.c
    src/tor/src/lib/container/order.c
    src/tor/src/lib/container/smartlist.c
    src/tor/src/lib/crypt_ops/aes_openssl.c
    src/tor/src/lib/crypt_ops/crypto_cipher.c
    src/tor/src/lib/crypt_ops/crypto_curve25519.c
    src/tor/src/lib/crypt_ops/crypto_dh.c
    src/tor/src/lib/crypt_ops/crypto_dh_openssl.c
    src/tor/src/lib/crypt_ops/crypto_digest.c
    src/tor/src/lib/crypt_ops/crypto_digest_openssl.c
    src/tor/src/lib/crypt_ops/crypto_ed25519.c
    src/tor/src/lib/crypt_ops/crypto_format.c
    src/tor/src/lib/crypt_ops/crypto_hkdf.c
    src/tor/src/lib/crypt_ops/crypto_init.c
    src/tor/src/lib/crypt_ops/crypto_ope.c
    src/tor/src/lib/crypt_ops/crypto_openssl_mgt.c
    src/tor/src/lib/crypt_ops/crypto_pwbox.c
    src/tor/src/lib/crypt_ops/crypto_rand.c
    src/tor/src/lib/crypt_ops/crypto_rand_fast.c
    src/tor/src/lib/crypt_ops/crypto_rand_numeric.c
    src/tor/src/lib/crypt_ops/crypto_rsa.c
    src/tor/src/lib/crypt_ops/crypto_rsa_openssl.c
    src/tor/src/lib/crypt_ops/crypto_s2k.c
    src/tor/src/lib/crypt_ops/crypto_util.c
    src/tor/src/lib/crypt_ops/digestset.c
    src/tor/src/lib/ctime/di_ops.c
    src/tor/src/lib/dispatch/dispatch_cfg.c
    src/tor/src/lib/dispatch/dispatch_core.c
    src/tor/src/lib/dispatch/dispatch_naming.c
    src/tor/src/lib/dispatch/dispatch_new.c
    src/tor/src/lib/encoding/binascii.c
    src/tor/src/lib/encoding/confline.c
    src/tor/src/lib/encoding/cstring.c
    src/tor/src/lib/encoding/keyval.c
    src/tor/src/lib/encoding/kvline.c
    src/tor/src/lib/encoding/pem.c
    src/tor/src/lib/encoding/qstring.c
    src/tor/src/lib/encoding/time_fmt.c
    src/tor/src/lib/err/backtrace.c
    src/tor/src/lib/err/torerr.c
    src/tor/src/lib/err/torerr_sys.c
    src/tor/src/lib/evloop/compat_libevent.c
    src/tor/src/lib/evloop/evloop_sys.c
    src/tor/src/lib/evloop/procmon.c
    src/tor/src/lib/evloop/timers.c
    src/tor/src/lib/evloop/token_bucket.c
    src/tor/src/lib/evloop/workqueue.c
    src/tor/src/lib/fdio/fdio.c
    src/tor/src/lib/fs/conffile.c
    src/tor/src/lib/fs/dir.c
    src/tor/src/lib/fs/files.c
    src/tor/src/lib/fs/freespace.c
    src/tor/src/lib/fs/lockfile.c
    src/tor/src/lib/fs/mmap.c
    src/tor/src/lib/fs/path.c
    src/tor/src/lib/fs/storagedir.c
    src/tor/src/lib/fs/userdb.c
    src/tor/src/lib/geoip/geoip.c
    src/tor/src/lib/intmath/addsub.c
    src/tor/src/lib/intmath/bits.c
    src/tor/src/lib/intmath/muldiv.c
    src/tor/src/lib/intmath/weakrng.c
    src/tor/src/lib/llharden/winprocess_sys.c
    src/tor/src/lib/lock/compat_mutex.c
    src/tor/src/lib/lock/compat_mutex_pthreads.c
    src/tor/src/lib/log/escape.c
    src/tor/src/lib/log/log.c
    src/tor/src/lib/log/log_sys.c
    src/tor/src/lib/log/ratelim.c
    src/tor/src/lib/log/util_bug.c
    src/tor/src/lib/malloc/malloc.c
    src/tor/src/lib/malloc/map_anon.c
    src/tor/src/lib/math/fp.c
    src/tor/src/lib/math/laplace.c
    src/tor/src/lib/math/prob_distr.c
    src/tor/src/lib/memarea/memarea.c
    src/tor/src/lib/meminfo/meminfo.c
    src/tor/src/lib/metrics/metrics_common.c
    src/tor/src/lib/metrics/metrics_store.c
    src/tor/src/lib/metrics/metrics_store_entry.c
    src/tor/src/lib/metrics/prometheus.c
    src/tor/src/lib/net/address.c
    src/tor/src/lib/net/alertsock.c
    src/tor/src/lib/net/buffers_net.c
    src/tor/src/lib/net/gethostname.c
    src/tor/src/lib/net/inaddr.c
    src/tor/src/lib/net/network_sys.c
    src/tor/src/lib/net/resolve.c
    src/tor/src/lib/net/socket.c
    src/tor/src/lib/net/socketpair.c
    src/tor/src/lib/osinfo/libc.c
    src/tor/src/lib/osinfo/uname.c
    src/tor/src/lib/process/daemon.c
    src/tor/src/lib/process/env.c
    src/tor/src/lib/process/pidfile.c
    src/tor/src/lib/process/process.c
    src/tor/src/lib/process/process_sys.c
    src/tor/src/lib/process/process_unix.c
    src/tor/src/lib/process/process_win32.c
    src/tor/src/lib/process/restrict.c
    src/tor/src/lib/process/setuid.c
    src/tor/src/lib/process/waitpid.c
    src/tor/src/lib/pubsub/pubsub_build.c
    src/tor/src/lib/pubsub/pubsub_check.c
    src/tor/src/lib/pubsub/pubsub_publish.c
    src/tor/src/lib/sandbox/sandbox.c
    src/tor/src/lib/smartlist_core/smartlist_core.c
    src/tor/src/lib/smartlist_core/smartlist_split.c
    src/tor/src/lib/string/compat_ctype.c
    src/tor/src/lib/string/compat_string.c
    src/tor/src/lib/string/parse_int.c
    src/tor/src/lib/string/printf.c
    src/tor/src/lib/string/scanf.c
    src/tor/src/lib/string/util_string.c
    src/tor/src/lib/term/getpass.c
    src/tor/src/lib/thread/compat_pthreads.c
    src/tor/src/lib/thread/compat_threads.c
    src/tor/src/lib/thread/numcpus.c
    src/tor/src/lib/time/compat_time.c
    src/tor/src/lib/time/time_sys.c
    src/tor/src/lib/time/tvdiff.c
    src/tor/src/lib/tls/buffers_tls.c
    src/tor/src/lib/tls/tortls.c
    src/tor/src/lib/tls/tortls_openssl.c
    src/tor/src/lib/tls/x509.c
    src/tor/src/lib/tls/x509_openssl.c
    src/tor/src/lib/trace/trace_stub.c
    src/tor/src/lib/version/git_revision.c
    src/tor/src/lib/version/version.c
    src/tor/src/lib/wallclock/approx_time.c
    src/tor/src/lib/wallclock/time_to_tm.c
    src/tor/src/lib/wallclock/tor_gettimeofday.c
    src/tor/src/trunnel/channelpadding_negotiation.c
    src/tor/src/trunnel/circpad_negotiation.c
    src/tor/src/trunnel/conflux.c
    src/tor/src/trunnel/congestion_control.c
    src/tor/src/trunnel/ed25519_cert.c
    src/tor/src/trunnel/extension.c
    src/tor/src/trunnel/flow_control_cells.c
    src/tor/src/trunnel/hs/cell_establish_intro.c
    src/tor/src/trunnel/hs/cell_introduce1.c
    src/tor/src/trunnel/hs/cell_rendezvous.c
    src/tor/src/trunnel/link_handshake.c
    src/tor/src/trunnel/netinfo.c
    src/tor/src/trunnel/pwbox.c
    src/tor/src/trunnel/sendme_cell.c
    src/tor/src/trunnel/socks5.c
    src/tor/src/trunnel/subproto_request.c
    src/echo.c
    src/jh.c
    src/keccak.c
    src/scrypt-arm.S
    src/scrypt-x86.S
    src/scrypt-x86_64.S
)

# clang reads .S as assembler-with-cpp; each file guards its whole body on the
# target architecture, so the two that do not match assemble to nothing.
set_source_files_properties(
    src/scrypt-arm.S src/scrypt-x86.S src/scrypt-x86_64.S
    PROPERTIES LANGUAGE ASM)

add_library(innova_c STATIC ${INNOVA_C_SOURCES})
# Nothing here is a Qt class; without this the global AUTOMOC adds a C++
# translation unit to a target carrying C-only flags.
set_target_properties(innova_c PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
target_compile_definitions(innova_c PRIVATE
    ${INNOVA_DEFINES}
    HAVE_CONFIG_H TRUNNEL_LOCAL_H
    ED25519_CUSTOMRANDOM ED25519_CUSTOMHASH ED25519_SUFFIX=_donna)
# tor's own directories must precede src: src carries a stale copy of tor's
# ed25519 tree that nothing compiles, and -Isrc first satisfies tor's
# "ed25519/donna/..." includes from it.
target_include_directories(innova_c BEFORE PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tor
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tor/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tor/src/ext
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tor/src/ext/trunnel
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tor/src/trunnel)
target_include_directories(innova_c PRIVATE ${INNOVA_INCLUDES})
target_compile_options(innova_c PRIVATE
    -std=gnu99 -fwrapv -pthread
    -Wno-incompatible-pointer-types -Wno-unused-parameter
    -Wno-missing-field-initializers -Wno-implicit-fallthrough
    -Wno-sign-compare -Wno-unused-but-set-variable)

# ---- C++/ObjC++ sources, forms and resources ----
set(INNOVA_CXX_SOURCES
    src/ipfs.cc
    src/ipfscurl.cc
    src/tor/anonymize.cpp
    src/txdb-leveldb.cpp
    src/hash.cpp
    src/qt/bitcoin.cpp
    src/qt/bitcoingui.cpp
    src/qt/initexecutor.cpp
    src/qt/intro.cpp
    src/qt/transactiontablemodel.cpp
    src/qt/addresstablemodel.cpp
    src/qt/peertablemodel.cpp
    src/qt/optionsdialog.cpp
    src/qt/sendcoinsdialog.cpp
    src/qt/coincontroldialog.cpp
    src/qt/coincontroltreewidget.cpp
    src/qt/addressbookpage.cpp
    src/qt/signverifymessagedialog.cpp
    src/qt/aboutdialog.cpp
    src/qt/editaddressdialog.cpp
    src/qt/bitcoinaddressvalidator.cpp
    src/qt/statisticspage.cpp
    src/qt/blockbrowser.cpp
    src/qt/marketbrowser.cpp
    src/kernelrecord.cpp
    src/qt/mintingfilterproxy.cpp
    src/qt/mintingtablemodel.cpp
    src/qt/mintingview.cpp
    src/qt/multisigaddressentry.cpp
    src/qt/multisiginputentry.cpp
    src/qt/multisigdialog.cpp
    src/qt/proofofimage.cpp
    src/qt/hyperfile.cpp
    src/qt/stakingpage.cpp
    src/qt/privacypage.cpp
    src/qt/iv5rpcbridge.cpp
    src/qt/disclosuremaskwidget.cpp
    src/qt/finalitystatuswidget.cpp
    src/qt/privatecollateralwidget.cpp
    src/qt/nullsendmixwidget.cpp
    src/qt/chatwidget.cpp
    src/qt/emojipicker.cpp
    src/qt/walletworker.cpp
    src/rpchyperfile.cpp
    src/qt/termsofuse.cpp
    src/qt/bantablemodel.cpp
    src/alert.cpp
    src/stun.cpp
    src/base58.cpp
    src/version.cpp
    src/sync.cpp
    src/smessage.cpp
    src/util.cpp
    src/netbase.cpp
    src/key.cpp
    src/bip39.cpp
    src/bip39_wordlist.cpp
    src/hdroot.cpp
    src/script.cpp
    src/main.cpp
    src/core.cpp
    src/bloom.cpp
    src/state.cpp
    src/ringsig.cpp
    src/miner.cpp
    src/init.cpp
    src/bootstrap.cpp
    src/net.cpp
    src/checkpoints.cpp
    src/addrman.cpp
    src/db.cpp
    src/utiltime.cpp
    src/eccryptoverify.cpp
    src/walletdb.cpp
    src/qt/clientmodel.cpp
    src/qt/guiutil.cpp
    src/qt/uriutil.cpp
    src/qt/stakinguipolicy.cpp
    src/qt/privacyuipolicy.cpp
    src/qt/transactionrecord.cpp
    src/qt/optionsmodel.cpp
    src/qt/monitoreddatamapper.cpp
    src/qt/transactiondesc.cpp
    src/qt/transactiondescdialog.cpp
    src/qt/bitcoinstrings.cpp
    src/qt/bitcoinamountfield.cpp
    src/wallet.cpp
    src/keystore.cpp
    src/qt/transactionfilterproxy.cpp
    src/qt/transactionview.cpp
    src/qt/qrcodedialog.cpp
    src/qt/walletmodel.cpp
    src/innovarpc.cpp
    src/rpcdump.cpp
    src/rpcnet.cpp
    src/rpcmining.cpp
    src/rpcwallet.cpp
    src/rpccollateral.cpp
    src/rpcblockchain.cpp
    src/pod.cpp
    src/rpcrawtransaction.cpp
    src/rpcsmessage.cpp
    src/rpcnyx.cpp
    src/qt/overviewpage.cpp
    src/qt/csvmodelwriter.cpp
    src/crypter.cpp
    src/qt/sendcoinsentry.cpp
    src/qt/qvalidatedlineedit.cpp
    src/qt/bitcoinunits.cpp
    src/qt/qvaluecombobox.cpp
    src/qt/askpassphrasedialog.cpp
    src/qt/recoveryphrasedialog.cpp
    src/qt/iv5seeddialog.cpp
    src/qt/iv5holdswidget.cpp
    src/protocol.cpp
    src/qt/notificator.cpp
    src/qt/qtipcserver.cpp
    src/qt/rpcconsole.cpp
    src/qt/trafficgraphwidget.cpp
    src/qt/idagpage.cpp
    src/qt/nametablemodel.cpp
    src/qt/managenamespage.cpp
    src/qt/messagemodel.cpp
    src/qt/qcustomplot.cpp
    src/qt/sendmessagesdialog.cpp
    src/qt/sendmessagesentry.cpp
    src/qt/qvalidatedtextedit.cpp
    src/qt/plugins/mrichtexteditor/mrichtextedit.cpp
    src/qt/collateralnodemanager.cpp
    src/qt/addeditadrenalinenode.cpp
    src/qt/adrenalinenodeconfigdialog.cpp
    src/noui.cpp
    src/kernel.cpp
    src/scrypt.cpp
    src/pbkdf2.cpp
    src/stealth.cpp
    src/idns.cpp
    src/idnsdescriptor.cpp
    src/namecoin.cpp
    src/collateral.cpp
    src/activecollateralnode.cpp
    src/collateralnode.cpp
    src/collateralnodeconfig.cpp
    src/spork.cpp
    src/shielded.cpp
    src/privacy_vnext_ffi.cpp
    src/nullsend.cpp
    src/nullsend_v2008.cpp
    src/nullsend_driver.cpp
    src/rpcshielded.cpp
    src/zkproof.cpp
    src/verifycache.cpp
    src/lelantus.cpp
    src/curvetree.cpp
    src/ipa.cpp
    src/ed25519_zk.cpp
    src/nullstake.cpp
    src/poseidon2.cpp
    src/bulletproof_ac.cpp
    src/silentpayments.cpp
    src/dandelion.cpp
    src/finality.cpp
    src/finality_schedule.cpp
    src/privacy_vnext_builder.cpp
    src/privacy_vnext_store.cpp
    src/subsidy.cpp
    src/finality_note.cpp
    src/dag.cpp
    src/mstimestamp.cpp
    src/blockprofile.cpp
    src/qt/macdockiconhandler.mm
    src/qt/macnotificationhandler.mm
)

set(INNOVA_HEADERS
    src/qt/bitcoingui.h
    src/qt/intro.h
    src/qt/transactiontablemodel.h
    src/qt/addresstablemodel.h
    src/qt/peertablemodel.h
    src/qt/optionsdialog.h
    src/qt/coincontroldialog.h
    src/qt/coincontroltreewidget.h
    src/qt/sendcoinsdialog.h
    src/qt/addressbookpage.h
    src/qt/signverifymessagedialog.h
    src/qt/aboutdialog.h
    src/qt/editaddressdialog.h
    src/qt/bitcoinaddressvalidator.h
    src/kernelrecord.h
    src/qt/mintingfilterproxy.h
    src/qt/mintingtablemodel.h
    src/qt/mintingview.h
    src/qt/proofofimage.h
    src/qt/hyperfile.h
    src/qt/stakingpage.h
    src/qt/privacypage.h
    src/qt/iv5rpcbridge.h
    src/qt/disclosuremaskwidget.h
    src/qt/finalitystatuswidget.h
    src/qt/privatecollateralwidget.h
    src/qt/nullsendmixwidget.h
    src/qt/chatwidget.h
    src/qt/emojipicker.h
    src/qt/walletworker.h
    src/qt/multisigaddressentry.h
    src/qt/multisiginputentry.h
    src/qt/multisigdialog.h
    src/qt/bantablemodel.h
    src/alert.h
    src/addrman.h
    src/base58.h
    src/bignum.h
    src/checkpoints.h
    src/compat.h
    src/coincontrol.h
    src/sync.h
    src/tinyformat.h
    src/util.h
    src/uint256.h
    src/kernel.h
    src/scrypt.h
    src/pbkdf2.h
    src/serialize.h
    src/strlcpy.h
    src/smessage.h
    src/main.h
    src/core.h
    src/state.h
    src/ringsig.h
    src/miner.h
    src/net.h
    src/key.h
    src/bip39.h
    src/bip39_wordlist.h
    src/hdroot.h
    src/db.h
    src/txdb.h
    src/walletdb.h
    src/script.h
    src/stealth.h
    src/idns.h
    src/idnsdescriptor.h
    src/hooks.h
    src/namecoin.h
    src/collateral.h
    src/activecollateralnode.h
    src/collateralnode.h
    src/collateralnodeconfig.h
    src/spork.h
    src/shielded.h
    src/nullsend.h
    src/nullsend_v2008.h
    src/nullsend_driver.h
    src/zkproof.h
    src/verifycache.h
    src/lelantus.h
    src/curvetree.h
    src/ipa.h
    src/ed25519_zk.h
    src/nullstake.h
    src/poseidon2.h
    src/bulletproof_ac.h
    src/silentpayments.h
    src/dandelion.h
    src/finality.h
    src/finality_schedule.h
    src/privacy_vnext_builder.h
    src/privacy_vnext_store.h
    src/subsidy.h
    src/finality_note.h
    src/dag.h
    src/mstimestamp.h
    src/blockprofile.h
    src/init.h
    src/bootstrap.h
    src/mruset.h
    src/utiltime.h
    src/openssl_compat.h
    src/json/json_spirit_writer_template.h
    src/json/json_spirit_writer.h
    src/json/json_spirit_value.h
    src/json/json_spirit_utils.h
    src/json/json_spirit_stream_reader.h
    src/json/json_spirit_reader_template.h
    src/json/json_spirit_reader.h
    src/json/json_spirit_error_position.h
    src/json/json_spirit.h
    src/qt/clientmodel.h
    src/qt/guiutil.h
    src/qt/transactionrecord.h
    src/qt/guiconstants.h
    src/qt/optionsmodel.h
    src/qt/monitoreddatamapper.h
    src/qt/transactiondesc.h
    src/qt/transactiondescdialog.h
    src/qt/bitcoinamountfield.h
    src/wallet.h
    src/keystore.h
    src/qt/transactionfilterproxy.h
    src/qt/transactionview.h
    src/qt/walletmodel.h
    src/innovarpc.h
    src/pod.h
    src/qt/overviewpage.h
    src/qt/csvmodelwriter.h
    src/crypter.h
    src/qt/sendcoinsentry.h
    src/qt/qvalidatedlineedit.h
    src/qt/bitcoinunits.h
    src/qt/qvaluecombobox.h
    src/qt/askpassphrasedialog.h
    src/qt/recoveryphrasedialog.h
    src/qt/iv5seeddialog.h
    src/qt/iv5holdswidget.h
    src/protocol.h
    src/qt/notificator.h
    src/qt/qtipcserver.h
    src/allocators.h
    src/ui_interface.h
    src/qt/rpcconsole.h
    src/qt/trafficgraphwidget.h
    src/qt/blockbrowser.h
    src/qt/idagpage.h
    src/qt/statisticspage.h
    src/qt/marketbrowser.h
    src/qt/qcustomplot.h
    src/qt/collateralnodemanager.h
    src/qt/addeditadrenalinenode.h
    src/qt/adrenalinenodeconfigdialog.h
    src/qt/termsofuse.h
    src/version.h
    src/bloom.h
    src/netbase.h
    src/clientversion.h
    src/hash.h
    src/hashblock.h
    src/sph_echo.h
    src/sph_keccak.h
    src/sph_jh.h
    src/sph_types.h
    src/threadsafety.h
    src/eccryptoverify.h
    src/qt/nametablemodel.h
    src/qt/managenamespage.h
    src/qt/messagemodel.h
    src/qt/sendmessagesdialog.h
    src/qt/sendmessagesentry.h
    src/qt/initexecutor.h
    src/qt/plugins/mrichtexteditor/mrichtextedit.h
    src/qt/qvalidatedtextedit.h
    src/qt/uriutil.h
    src/qt/stakinguipolicy.h
    src/qt/privacyuipolicy.h
    src/qt/qrcodedialog.h
)

set(INNOVA_FORMS
    src/qt/forms/intro.ui
    src/qt/forms/coincontroldialog.ui
    src/qt/forms/sendcoinsdialog.ui
    src/qt/forms/addressbookpage.ui
    src/qt/forms/signverifymessagedialog.ui
    src/qt/forms/aboutdialog.ui
    src/qt/forms/editaddressdialog.ui
    src/qt/forms/transactiondescdialog.ui
    src/qt/forms/overviewpage.ui
    src/qt/forms/sendcoinsentry.ui
    src/qt/forms/askpassphrasedialog.ui
    src/qt/forms/rpcconsole.ui
    src/qt/forms/optionsdialog.ui
    src/qt/forms/statisticspage.ui
    src/qt/forms/blockbrowser.ui
    src/qt/forms/marketbrowser.ui
    src/qt/forms/proofofimage.ui
    src/qt/forms/hyperfile.ui
    src/qt/forms/termsofuse.ui
    src/qt/forms/collateralnodemanager.ui
    src/qt/forms/addeditadrenalinenode.ui
    src/qt/forms/adrenalinenodeconfigdialog.ui
    src/qt/forms/multisigaddressentry.ui
    src/qt/forms/multisiginputentry.ui
    src/qt/forms/multisigdialog.ui
    src/qt/forms/managenamespage.ui
    src/qt/forms/sendmessagesentry.ui
    src/qt/forms/sendmessagesdialog.ui
    src/qt/plugins/mrichtexteditor/mrichtextedit.ui
    src/qt/forms/qrcodedialog.ui
)

set(INNOVA_RESOURCES
    src/qt/bitcoin.qrc
    src/qt/res/themes/qdarkstyle/style.qrc
)


qt6_wrap_ui(INNOVA_UI_HEADERS ${INNOVA_FORMS})

add_executable(Innova MACOSX_BUNDLE
    ${INNOVA_CXX_SOURCES} ${INNOVA_HEADERS} ${INNOVA_UI_HEADERS} ${INNOVA_RESOURCES})

add_dependencies(Innova genbuild)

# bitcoin.qrc embeds the compiled translations; a checkout carries only the .ts sources.
find_program(INNOVA_LRELEASE NAMES lrelease lrelease-qt6
    HINTS ${QT6_INSTALL_PREFIX}/bin /opt/homebrew/opt/qttools/bin /usr/local/opt/qttools/bin
          /usr/lib/qt6/bin /usr/lib/x86_64-linux-gnu/qt6/bin)
if(NOT INNOVA_LRELEASE)
    message(FATAL_ERROR "lrelease not found: install the Qt 6 Linguist tools (brew install qttools, or qt6-l10n-tools)")
endif()
file(GLOB INNOVA_TS_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/qt/locale/bitcoin_*.ts)
set(INNOVA_QM_FILES)
foreach(ts ${INNOVA_TS_FILES})
    get_filename_component(ts_name ${ts} NAME_WE)
    set(qm ${CMAKE_CURRENT_SOURCE_DIR}/src/qt/locale/${ts_name}.qm)
    add_custom_command(OUTPUT ${qm}
        COMMAND ${INNOVA_LRELEASE} -silent ${ts} -qm ${qm}
        DEPENDS ${ts} VERBATIM)
    list(APPEND INNOVA_QM_FILES ${qm})
endforeach()
add_custom_target(translations DEPENDS ${INNOVA_QM_FILES})
add_dependencies(Innova translations)
target_compile_definitions(Innova PRIVATE ${INNOVA_DEFINES})
target_include_directories(Innova PRIVATE ${INNOVA_INCLUDES})
target_compile_options(Innova PRIVATE
    -fstack-protector-all --param ssp-buffer-size=1 -pthread
    -Wno-deprecated-declarations -Wno-literal-suffix
    -Wno-ignored-qualifiers -Wno-format -Wno-unused-parameter)

find_library(FW_FOUNDATION Foundation REQUIRED)
find_library(FW_APPSERVICES ApplicationServices REQUIRED)
find_library(FW_APPKIT AppKit REQUIRED)
find_library(FW_DISKARB DiskArbitration REQUIRED)
find_library(FW_IOKIT IOKit REQUIRED)

set(IV5_RUST_LIB ${CMAKE_CURRENT_SOURCE_DIR}/src/privacy_vnext/rust/target/release/libinnova_privacy_vnext.a)

target_link_directories(Innova PRIVATE
    ${HB}/opt/boost/lib ${HB}/opt/berkeley-db@5/lib
    ${HB}/opt/openssl@3/lib ${HB}/opt/libevent/lib ${HB}/opt/curl/lib
    ${HB}/opt/qrencode/lib)

target_link_libraries(Innova PRIVATE
    innova_c
    ${IV5_RUST_LIB}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/leveldb/libleveldb.a
    ${CMAKE_CURRENT_SOURCE_DIR}/src/leveldb/libmemenv.a
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::Concurrent Qt6::PrintSupport
    curl ssl crypto db_cxx z event qrencode
    boost_filesystem boost_program_options boost_thread boost_chrono
    ${FW_FOUNDATION} ${FW_APPSERVICES} ${FW_APPKIT}
    ${FW_DISKARB} ${FW_IOKIT})

# The bundle icon. Without it macOS draws the generic blank document tile, which
# is what a bundle carrying no icon resource gets; the .pro sets the same file.
set_source_files_properties(src/qt/res/icons/innova.icns
    PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
target_sources(Innova PRIVATE src/qt/res/icons/innova.icns)

set_target_properties(Innova PROPERTIES
    MACOSX_BUNDLE_ICON_FILE innova.icns
    MACOSX_BUNDLE_BUNDLE_NAME Innova
    MACOSX_BUNDLE_GUI_IDENTIFIER org.innova.Innova
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION})

# Homebrew's Qt6 keg is not linked into the prefix, so the bundle cannot find
# its platform plugin by the usual relative lookup. A qt.conf in Resources
# names the keg's plugin directory and keeps the bundle runnable in place.
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/qt.conf
     "[Paths]\nPlugins = ${QT6_INSTALL_PREFIX}/${QT6_INSTALL_PLUGINS}\n")
target_sources(Innova PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/qt.conf)
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/qt.conf
    PROPERTIES MACOSX_PACKAGE_LOCATION Resources)

# An unsigned bundle is removed by the OS shortly after link when the build runs
# from a non-interactive shell. An ad-hoc signature settles it at link time.
add_custom_command(TARGET Innova POST_BUILD
    COMMAND codesign --force --sign - --timestamp=none
            $<TARGET_BUNDLE_DIR:Innova>
    COMMENT "ad-hoc signing the bundle")

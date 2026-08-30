TEMPLATE = app
TARGET = Innova
VERSION = 5.0.0.0
INCLUDEPATH += src src/json src/qt src/qt/plugins/mrichtexteditor
DEFINES += QT_GUI BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE
CONFIG += no_include_pwd
CONFIG += thread
CONFIG += static
CONFIG += c++17
QT += core gui network widgets concurrent

# macOS: Detect Homebrew prefix early (arm64 uses /opt/homebrew, x86_64 uses /usr/local)
macx {
    HOMEBREW_PREFIX = /opt/homebrew
    exists(/usr/local/bin/brew):!exists(/opt/homebrew/bin/brew) {
        HOMEBREW_PREFIX = /usr/local
    }
}

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
lessThan(QT_MAJOR_VERSION, 5): CONFIG += static
QMAKE_CXXFLAGS += -Wno-literal-suffix
QMAKE_CFLAGS += -std=c99 -Wno-incompatible-pointer-types
unix|macx:QMAKE_MAKE = $$PWD/contrib/innova_make.sh

greaterThan(QT_MAJOR_VERSION, 4) {
    QT += widgets printsupport
    DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0
}

linux {
    QMAKE_CFLAGS += -std=gnu99
}

win32 {
BOOST_LIB_SUFFIX=-mt

MSYS2_MINGW64 = $$(MINGW_PREFIX)
isEmpty(MSYS2_MINGW64): MSYS2_MINGW64 = C:/msys64/mingw64
exists($$MSYS2_MINGW64/include/boost/version.hpp) {
    message(Auto-detected MSYS2 MINGW64 at $$MSYS2_MINGW64)
    BOOST_THREAD_LIB_SUFFIX = -mt
    BOOST_INCLUDE_PATH = $$MSYS2_MINGW64/include
    BOOST_LIB_PATH = $$MSYS2_MINGW64/lib
    BDB_INCLUDE_PATH = $$MSYS2_MINGW64/include
    BDB_LIB_PATH = $$MSYS2_MINGW64/lib
    OPENSSL_INCLUDE_PATH = $$MSYS2_MINGW64/include
    OPENSSL_LIB_PATH = $$MSYS2_MINGW64/lib
    MINIUPNPC_INCLUDE_PATH = $$MSYS2_MINGW64/include
    MINIUPNPC_LIB_PATH = $$MSYS2_MINGW64/lib
    QRENCODE_INCLUDE_PATH = $$MSYS2_MINGW64/include
    QRENCODE_LIB_PATH = $$MSYS2_MINGW64/lib
    LIBEVENT_INCLUDE_PATH = $$MSYS2_MINGW64/include
    LIBEVENT_LIB_PATH = $$MSYS2_MINGW64/lib
    LIBCURL_INCLUDE_PATH = $$MSYS2_MINGW64/include
    LIBCURL_LIB_PATH = $$MSYS2_MINGW64/lib
} else {
    # Legacy manual dependency paths (C:/deps/ layout)
    BOOST_THREAD_LIB_SUFFIX = _win32-mt
    BOOST_INCLUDE_PATH = C:/deps/boost_1_57_0
    BOOST_LIB_PATH = C:/deps/boost_1_57_0/stage/lib
    BDB_INCLUDE_PATH = C:/deps/db-4.8.30.NC/build_unix
    BDB_LIB_PATH = C:/deps/db-4.8.30.NC/build_unix
    OPENSSL_INCLUDE_PATH = C:/deps/openssl/include
    OPENSSL_LIB_PATH = C:/deps/openssl
    MINIUPNPC_INCLUDE_PATH = C:/deps/miniupnp
    MINIUPNPC_LIB_PATH = C:/deps/miniupnp/miniupnpc
    QRENCODE_INCLUDE_PATH = C:/deps/qrencode-3.4.4
    QRENCODE_LIB_PATH = C:/deps/qrencode-3.4.4/.libs
    LIBEVENT_INCLUDE_PATH = C:/deps/libevent/include
    LIBEVENT_LIB_PATH = C:/deps/libevent/.libs
    LIBCURL_INCLUDE_PATH = C:/deps/libcurl/include
    LIBCURL_LIB_PATH = C:/deps/libcurl/lib
}
}

# for boost 1.37, add -mt to the boost libraries
# use: qmake BOOST_LIB_SUFFIX=-mt
# for boost thread win32 with _win32 sufix
# use: BOOST_THREAD_LIB_SUFFIX=_win32-...
# or when linking against a specific BerkelyDB version: BDB_LIB_SUFFIX=-4.8

# Dependency library locations can be customized with:
#    BOOST_INCLUDE_PATH, BOOST_LIB_PATH, BDB_INCLUDE_PATH,
#    BDB_LIB_PATH, OPENSSL_INCLUDE_PATH and OPENSSL_LIB_PATH respectively

OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build

IV5_RUST_DIR = $$PWD/src/privacy_vnext/rust
IV5_RUST_PROFILE = debug
IV5_RUST_FLAGS =
contains(RELEASE, 1) {
    IV5_RUST_PROFILE = release
    IV5_RUST_FLAGS = --release
}
win32-msvc:IV5_RUST_LIB = $$IV5_RUST_DIR/target/$$IV5_RUST_PROFILE/innova_privacy_vnext.lib
else:IV5_RUST_LIB = $$IV5_RUST_DIR/target/$$IV5_RUST_PROFILE/libinnova_privacy_vnext.a
privacy_vnext_rust.target = $$IV5_RUST_LIB
# Without a dependency the archive is up to date once it exists and cargo never
# runs again, linking whatever decoder was built first. Cargo tracks the real
# sources, and a no-op build leaves the archive alone, so defer to it.
privacy_vnext_rust.depends = FORCE
win32:privacy_vnext_rust.commands = cd /d $$shell_path($$IV5_RUST_DIR) && cargo build --locked --offline $$IV5_RUST_FLAGS
else:privacy_vnext_rust.commands = cd $$shell_path($$IV5_RUST_DIR) && cargo build --locked --offline $$IV5_RUST_FLAGS
QMAKE_EXTRA_TARGETS += privacy_vnext_rust
PRE_TARGETDEPS += $$IV5_RUST_LIB
LIBS = $$IV5_RUST_LIB $$LIBS

# use: qmake "RELEASE=1"
contains(RELEASE, 1) {
    # Mac: compile for modern macOS
    macx:QMAKE_CXXFLAGS += -mmacosx-version-min=12.0



    !windows:!macx {
        # Linux: static link
        LIBS += -Wl,-Bstatic
    }
}

!win32 {
# for extra security against potential buffer overflows: enable GCCs Stack Smashing Protection
QMAKE_CXXFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
QMAKE_LFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
# We need to exclude this for Windows cross compile with MinGW 4.2.x, as it will result in a non-working executable!
# This can be enabled for Windows, when we switch to MinGW >= 4.4.x.
}
# for extra security on Windows: enable ASLR and DEP via GCC linker flags
# win32:QMAKE_LFLAGS *= -Wl,--large-address-aware -static
# For fully static builds, pass "STATIC_LINK=1" to qmake
win32:contains(STATIC_LINK, 1): QMAKE_LFLAGS *= -static
# enable Windows ASLR and DEP for security hardening
win32:QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat
win32:QMAKE_LFLAGS += -static-libgcc -static-libstdc++
lessThan(QT_MAJOR_VERSION, 5): win32: QMAKE_LFLAGS *= -static

# use: qmake "USE_IPFS=1" ( enabled by default; default)
#  or: qmake "USE_IPFS=0" (disabled by default)
#  or: qmake "USE_IPFS=-" (not supported)
# I n n o v a IPFS - USE_IPFS=- to not compile with the IPFS C Library located in src/ipfs
contains(USE_IPFS, -) {
    message(Building without IPFS support)
} else {
    message(Building with IPFS support)
    count(USE_IPFS, 0) {
        USE_IPFS=1
    }
    DEFINES += USE_IPFS=$$USE_IPFS
    INCLUDEPATH += src/ipfs

	###IPFS C Library native integration sources
	SOURCES += src/ipfs.cc \
		src/ipfscurl.cc
}

INCLUDEPATH += src/minizip
QMAKE_CFLAGS += -Wno-incompatible-pointer-types
SOURCES += src/minizip/ioapi.c \
    src/minizip/unzip.c


# use: qmake "USE_NATIVETOR=1" ( enabled by default; default)
#  or: qmake "USE_NATIVETOR=0" (disabled by default)
#  or: qmake "USE_NATIVETOR=-" (not supported)
# I n n o v a Native Tor - USE_NATIVETOR=- to not compile with the Tor C Library by Tor Project located in src/tor
contains(USE_NATIVETOR, -) {
    message(Building without Native Tor support)
} else {
    message(Building with Native Tor support)
    count(USE_NATIVETOR, 0) {
        USE_NATIVETOR=1
    }
    DEFINES += USE_NATIVETOR=$$USE_NATIVETOR
    DEFINES += HAVE_CONFIG_H

    # Passed as QMAKE_CFLAGS rather than INCLUDEPATH on purpose. qmake emits
    # CFLAGS before INCPATH, and only for C sources, which is exactly the scope
    # the vendored tor needs: src/ carries a stale copy of tor's ed25519 tree
    # that nothing compiles, and INCLUDEPATH's -Isrc would otherwise satisfy
    # tor's own "ed25519/donna/..." includes from it.
    QMAKE_CFLAGS += -Isrc/tor -Isrc/tor/src -Isrc/tor/src/ext \
        -Isrc/tor/src/ext/trunnel -Isrc/tor/src/trunnel

    # Upstream tor is warning-clean under its own flag set, not under ours.
    QMAKE_CFLAGS += -Wno-unused-parameter -Wno-missing-field-initializers \
        -Wno-implicit-fallthrough -Wno-sign-compare -Wno-unused-but-set-variable

    # anonymize.cpp is the one C++ file here and needs src/tor on its path.
    INCLUDEPATH += src/tor

    # Objects mirror tor's directory tree so upstream basenames (main.c,
    # version.c) cannot collide with Innova's own objects.
    CONFIG += object_parallel_to_source

    ### Tor sources, generated from src/tor/tor_sources.txt by
    ### contrib/gen_tor_sources.py. Do not list sources here by hand.
    include(src/tor/tor_sources.pri)
}

# use: qmake "USE_QRCODE=1"
# libqrencode (http://fukuchi.org/works/qrencode/index.en.html) must be installed for support
contains(USE_QRCODE, 1) {
    message(Building with QRCode support)
    DEFINES += USE_QRCODE
    macx {
        INCLUDEPATH += $$HOMEBREW_PREFIX/opt/qrencode/include $$HOMEBREW_PREFIX/include
        LIBS += -L$$HOMEBREW_PREFIX/opt/qrencode/lib
    }
    LIBS += -lqrencode
}
contains(USE_PROFILER, 1) {
    QMAKE_LFLAGS += -pg
    QMAKE_CXXFLAGS += -pg
}

contains(USE_DEBUG_FLAGS, 1) {
    QMAKE_LFLAGS += -Og
    QMAKE_CXXFLAGS += -Og
}

# use: qmake "USE_UPNP=1" ( enabled by default; default)
#  or: qmake "USE_UPNP=0" (disabled by default)
#  or: qmake "USE_UPNP=-" (not supported)
# miniupnpc (http://miniupnp.free.fr/files/) must be installed for support
contains(USE_UPNP, -) {
    message(Building without UPNP support)
} else {
    message(Building with UPNP support)
    count(USE_UPNP, 0) {
        USE_UPNP=1
    }
    DEFINES += USE_UPNP=$$USE_UPNP MINIUPNP_STATICLIB
    INCLUDEPATH += $$MINIUPNPC_INCLUDE_PATH
    macx:INCLUDEPATH += /opt/homebrew/opt/miniupnpc/include
    LIBS += $$join(MINIUPNPC_LIB_PATH,,-L,) -lminiupnpc
    macx:LIBS += -L/opt/homebrew/opt/miniupnpc/lib
    win32:LIBS += -liphlpapi
}

# use: qmake "USE_DBUS=1" or qmake "USE_DBUS=0"
linux:count(USE_DBUS, 0) {
    USE_DBUS=1
}
contains(USE_DBUS, 1) {
    message(Building with DBUS (Freedesktop notifications) support)
    DEFINES += USE_DBUS
    QT += dbus
}

# use: qmake "USE_IPV6=1" ( enabled by default; default)
#  or: qmake "USE_IPV6=0" (disabled by default)
#  or: qmake "USE_IPV6=-" (not supported)
contains(USE_IPV6, -) {
    message(Building without IPv6 support)
} else {
    count(USE_IPV6, 0) {
        USE_IPV6=1
    }
    DEFINES += USE_IPV6=$$USE_IPV6
}

contains(BITCOIN_NEED_QT_PLUGINS, 1) {
    DEFINES += BITCOIN_NEED_QT_PLUGINS
    # Qt4-era text codec / accessibility plugins removed in Qt6 (were dead here: block is off by default)
}

# use: qmake "USE_LEVELDB=1" ( enabled by default; default)
#  or: qmake "USE_LEVELDB=0" (disabled by default)
#  or: qmake "USE_LEVELDB=-" (not supported)
contains(USE_LEVELDB, -) {
	message(Building with Berkeley DB transaction index)

	    SOURCES += src/txdb-bdb.cpp \
		src/hash.cpp \
		src/aes_helper.c \
		src/echo.c \
		src/jh.c \
		src/keccak.c

} else {
	message(Building with LevelDB transaction index)
	count(USE_LEVELDB, 0) {
        USE_LEVELDB=1
    }

	DEFINES += USE_LEVELDB

    INCLUDEPATH += src/leveldb/include src/leveldb/helpers
	LIBS += $$PWD/src/leveldb/libleveldb.a $$PWD/src/leveldb/libmemenv.a
	SOURCES += src/txdb-leveldb.cpp \
		src/hash.cpp \
		src/aes_helper.c \
		src/echo.c \
		src/jh.c \
		src/keccak.c
	!win32 {
		# we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
		genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a
	} else {
		# make an educated guess about what the ranlib command is called
		isEmpty(QMAKE_RANLIB) {
			QMAKE_RANLIB = $$replace(QMAKE_STRIP, strip, ranlib)
		}
		LIBS += -lshlwapi
		#genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX TARGET_OS=OS_WINDOWS_CROSSCOMPILE $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libleveldb.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libmemenv.a
	}
	genleveldb.target = $$PWD/src/leveldb/libleveldb.a
	genleveldb.depends = FORCE
	PRE_TARGETDEPS += $$PWD/src/leveldb/libleveldb.a
	QMAKE_EXTRA_TARGETS += genleveldb
	# Gross ugly hack that depends on qmake internals, unfortunately there is no other way to do it.
	QMAKE_CLEAN += $$PWD/src/leveldb/libleveldb.a; cd $$PWD/src/leveldb ; $(MAKE) clean

}

# regenerate src/build.h
!windows|contains(USE_BUILD_INFO, 1) {
    genbuild.depends = FORCE
    genbuild.commands = cd $$PWD; /bin/sh share/genbuild.sh $$OUT_PWD/build/build.h
    genbuild.target = $$OUT_PWD/build/build.h
    PRE_TARGETDEPS += $$OUT_PWD/build/build.h
    QMAKE_EXTRA_TARGETS += genbuild
    DEFINES += HAVE_BUILD_INFO
}

contains(USE_O3, 1) {
    message(Building O3 optimization flag)
    QMAKE_CXXFLAGS_RELEASE -= -O2
    QMAKE_CFLAGS_RELEASE -= -O2
    QMAKE_CXXFLAGS += -O3
    QMAKE_CFLAGS += -O3
}

*-g++-32 {
    message("32 platform, adding -msse2 flag")

    QMAKE_CXXFLAGS += -msse2
    QMAKE_CFLAGS += -msse2
}

QMAKE_CXXFLAGS_WARN_ON = -fdiagnostics-show-option -Wall -Wextra -Wno-ignored-qualifiers -Wno-format -Wno-unused-parameter -Wstack-protector

contains(STRICT_WARNINGS, 1) {
    QMAKE_CXXFLAGS += -Werror=return-type -Werror=format
}


# Input
DEPENDPATH += src src/json src/qt
HEADERS += src/qt/bitcoingui.h \
    src/qt/intro.h \
    src/qt/transactiontablemodel.h \
    src/qt/addresstablemodel.h \
    src/qt/peertablemodel.h \
    src/qt/optionsdialog.h \
    src/qt/coincontroldialog.h \
    src/qt/coincontroltreewidget.h \
    src/qt/sendcoinsdialog.h \
    src/qt/addressbookpage.h \
    src/qt/signverifymessagedialog.h \
    src/qt/aboutdialog.h \
    src/qt/editaddressdialog.h \
    src/qt/bitcoinaddressvalidator.h \
    src/kernelrecord.h \
    src/qt/mintingfilterproxy.h \
    src/qt/mintingtablemodel.h \
    src/qt/mintingview.h \
    src/qt/proofofimage.h \
    src/qt/hyperfile.h \
    src/qt/stakingpage.h \
    src/qt/privacypage.h \
    src/qt/iv5rpcbridge.h \
    src/qt/disclosuremaskwidget.h \
    src/qt/finalitystatuswidget.h \
    src/qt/privatecollateralwidget.h \
    src/qt/chatwidget.h \
    src/qt/emojipicker.h \
    src/qt/walletworker.h \
    src/qt/multisigaddressentry.h \
    src/qt/multisiginputentry.h \
    src/qt/multisigdialog.h \
    src/qt/bantablemodel.h \
    src/alert.h \
    src/addrman.h \
    src/base58.h \
    src/bignum.h \
    src/checkpoints.h \
    src/compat.h \
    src/coincontrol.h \
    src/sync.h \
    src/tinyformat.h \
    src/util.h \
    src/uint256.h \
    src/kernel.h \
    src/scrypt.h \
    src/pbkdf2.h \
    src/serialize.h \
    src/strlcpy.h \
    src/smessage.h \
    src/main.h \
    src/core.h \
    src/state.h \
    src/ringsig.h \
    src/miner.h \
    src/net.h \
    src/key.h \
    src/db.h \
    src/txdb.h \
    src/walletdb.h \
    src/script.h \
    src/stealth.h \
    src/idns.h \
    src/idnsdescriptor.h \
    src/hooks.h \
    src/namecoin.h \
    src/collateral.h \
    src/activecollateralnode.h \
    src/collateralnode.h \
    src/collateralnodeconfig.h \
    src/spork.h \
    src/shielded.h \
    src/nullsend.h \
    src/zkproof.h \
    src/verifycache.h \
    src/lelantus.h \
    src/curvetree.h \
    src/ipa.h \
    src/ed25519_zk.h \
    src/nullstake.h \
    src/poseidon2.h \
    src/bulletproof_ac.h \
    src/silentpayments.h \
    src/dandelion.h \
    src/finality.h \
    src/finality_schedule.h \
    src/privacy_vnext_builder.h \
    src/privacy_vnext_store.h \
    src/subsidy.h \
    src/finality_note.h \
    src/dag.h \
    src/mstimestamp.h \
    src/blockprofile.h \
    src/init.h \
    src/bootstrap.h \
    src/mruset.h \
    src/utiltime.h \
    src/openssl_compat.h \
    src/json/json_spirit_writer_template.h \
    src/json/json_spirit_writer.h \
    src/json/json_spirit_value.h \
    src/json/json_spirit_utils.h \
    src/json/json_spirit_stream_reader.h \
    src/json/json_spirit_reader_template.h \
    src/json/json_spirit_reader.h \
    src/json/json_spirit_error_position.h \
    src/json/json_spirit.h \
    src/qt/clientmodel.h \
    src/qt/guiutil.h \
    src/qt/transactionrecord.h \
    src/qt/guiconstants.h \
    src/qt/optionsmodel.h \
    src/qt/monitoreddatamapper.h \
    src/qt/transactiondesc.h \
    src/qt/transactiondescdialog.h \
    src/qt/bitcoinamountfield.h \
    src/wallet.h \
    src/keystore.h \
    src/qt/transactionfilterproxy.h \
    src/qt/transactionview.h \
    src/qt/walletmodel.h \
    src/innovarpc.h \
    src/pod.h \
    src/qt/overviewpage.h \
    src/qt/csvmodelwriter.h \
    src/crypter.h \
    src/qt/sendcoinsentry.h \
    src/qt/qvalidatedlineedit.h \
    src/qt/bitcoinunits.h \
    src/qt/qvaluecombobox.h \
    src/qt/askpassphrasedialog.h \
    src/protocol.h \
    src/qt/notificator.h \
    src/qt/qtipcserver.h \
    src/allocators.h \
    src/ui_interface.h \
    src/qt/rpcconsole.h \
    src/qt/trafficgraphwidget.h \
    src/qt/blockbrowser.h \
    src/qt/idagpage.h \
    src/qt/statisticspage.h \
    src/qt/marketbrowser.h \
    src/qt/qcustomplot.h \
    src/qt/collateralnodemanager.h \
    src/qt/addeditadrenalinenode.h \
    src/qt/adrenalinenodeconfigdialog.h \
    src/qt/termsofuse.h \
    src/version.h \
    src/bloom.h \
    src/netbase.h \
    src/clientversion.h \
    src/hash.h \
    src/hashblock.h \
    src/sph_echo.h \
    src/sph_keccak.h \
    src/sph_jh.h \
    src/sph_types.h \
    src/threadsafety.h \
    src/eccryptoverify.h \
    src/qt/nametablemodel.h \
    src/qt/managenamespage.h \
    src/qt/messagemodel.h \
    src/qt/sendmessagesdialog.h \
    src/qt/sendmessagesentry.h \
    src/qt/initexecutor.h \
    src/qt/plugins/mrichtexteditor/mrichtextedit.h \
    src/qt/qvalidatedtextedit.h \
    src/qt/uriutil.h \
    src/qt/stakinguipolicy.h \
    src/qt/privacyuipolicy.h

SOURCES += src/qt/bitcoin.cpp src/qt/bitcoingui.cpp \
    src/qt/initexecutor.cpp \
    src/qt/intro.cpp \
    src/qt/transactiontablemodel.cpp \
    src/qt/addresstablemodel.cpp \
    src/qt/peertablemodel.cpp \
    src/qt/optionsdialog.cpp \
    src/qt/sendcoinsdialog.cpp \
    src/qt/coincontroldialog.cpp \
    src/qt/coincontroltreewidget.cpp \
    src/qt/addressbookpage.cpp \
    src/qt/signverifymessagedialog.cpp \
    src/qt/aboutdialog.cpp \
    src/qt/editaddressdialog.cpp \
    src/qt/bitcoinaddressvalidator.cpp \
    src/qt/statisticspage.cpp \
    src/qt/blockbrowser.cpp \
    src/qt/marketbrowser.cpp \
    src/kernelrecord.cpp \
    src/qt/mintingfilterproxy.cpp \
    src/qt/mintingtablemodel.cpp \
    src/qt/mintingview.cpp \
    src/qt/multisigaddressentry.cpp \
    src/qt/multisiginputentry.cpp \
    src/qt/multisigdialog.cpp \
    src/qt/proofofimage.cpp \
    src/qt/hyperfile.cpp \
    src/qt/stakingpage.cpp \
    src/qt/privacypage.cpp \
    src/qt/iv5rpcbridge.cpp \
    src/qt/disclosuremaskwidget.cpp \
    src/qt/finalitystatuswidget.cpp \
    src/qt/privatecollateralwidget.cpp \
    src/qt/chatwidget.cpp \
    src/qt/emojipicker.cpp \
    src/qt/walletworker.cpp \
    src/rpchyperfile.cpp \
    src/qt/termsofuse.cpp \
    src/qt/bantablemodel.cpp \
    src/alert.cpp \
    src/stun.cpp \
    src/base58.cpp \
    src/version.cpp \
    src/sync.cpp \
    src/smessage.cpp \
    src/util.cpp \
    src/netbase.cpp \
    src/key.cpp \
    src/script.cpp \
    src/main.cpp \
    src/core.cpp \
    src/bloom.cpp \
    src/state.cpp \
    src/ringsig.cpp \
    src/miner.cpp \
    src/init.cpp \
    src/bootstrap.cpp \
    src/net.cpp \
    src/checkpoints.cpp \
    src/addrman.cpp \
    src/db.cpp \
    src/utiltime.cpp \
    src/eccryptoverify.cpp \
    src/walletdb.cpp \
    src/qt/clientmodel.cpp \
    src/qt/guiutil.cpp \
    src/qt/uriutil.cpp \
    src/qt/stakinguipolicy.cpp \
    src/qt/privacyuipolicy.cpp \
    src/qt/transactionrecord.cpp \
    src/qt/optionsmodel.cpp \
    src/qt/monitoreddatamapper.cpp \
    src/qt/transactiondesc.cpp \
    src/qt/transactiondescdialog.cpp \
    src/qt/bitcoinstrings.cpp \
    src/qt/bitcoinamountfield.cpp \
    src/wallet.cpp \
    src/keystore.cpp \
    src/qt/transactionfilterproxy.cpp \
    src/qt/transactionview.cpp \
    src/qt/walletmodel.cpp \
    src/innovarpc.cpp \
    src/rpcdump.cpp \
    src/rpcnet.cpp \
    src/rpcmining.cpp \
    src/rpcwallet.cpp \
    src/rpccollateral.cpp \
    src/rpcblockchain.cpp \
    src/pod.cpp \
    src/rpcrawtransaction.cpp \
    src/rpcsmessage.cpp \
    src/rpcnyx.cpp \
    src/qt/overviewpage.cpp \
    src/qt/csvmodelwriter.cpp \
    src/crypter.cpp \
    src/qt/sendcoinsentry.cpp \
    src/qt/qvalidatedlineedit.cpp \
    src/qt/bitcoinunits.cpp \
    src/qt/qvaluecombobox.cpp \
    src/qt/askpassphrasedialog.cpp \
    src/protocol.cpp \
    src/qt/notificator.cpp \
    src/qt/qtipcserver.cpp \
    src/qt/rpcconsole.cpp \
    src/qt/trafficgraphwidget.cpp \
    src/qt/idagpage.cpp \
    src/qt/nametablemodel.cpp \
    src/qt/managenamespage.cpp \
    src/qt/messagemodel.cpp \
    src/qt/qcustomplot.cpp \
    src/qt/sendmessagesdialog.cpp \
    src/qt/sendmessagesentry.cpp \
    src/qt/qvalidatedtextedit.cpp \
    src/qt/plugins/mrichtexteditor/mrichtextedit.cpp \
    src/qt/collateralnodemanager.cpp \
    src/qt/addeditadrenalinenode.cpp \
    src/qt/adrenalinenodeconfigdialog.cpp \
    src/noui.cpp \
    src/kernel.cpp \
    src/scrypt-arm.S \
    src/scrypt-x86.S \
    src/scrypt-x86_64.S \
    src/scrypt.cpp \
    src/pbkdf2.cpp \
    src/stealth.cpp \
    src/idns.cpp \
    src/idnsdescriptor.cpp \
	src/namecoin.cpp \
    src/collateral.cpp \
    src/activecollateralnode.cpp \
    src/collateralnode.cpp \
    src/collateralnodeconfig.cpp \
    src/spork.cpp \
    src/shielded.cpp \
    src/privacy_vnext_ffi.cpp \
    src/nullsend.cpp \
    src/rpcshielded.cpp \
    src/zkproof.cpp \
    src/verifycache.cpp \
    src/lelantus.cpp \
    src/curvetree.cpp \
    src/ipa.cpp \
    src/ed25519_zk.cpp \
    src/nullstake.cpp \
    src/poseidon2.cpp \
    src/bulletproof_ac.cpp \
    src/silentpayments.cpp \
    src/dandelion.cpp \
    src/finality.cpp \
    src/finality_schedule.cpp \
    src/privacy_vnext_builder.cpp \
    src/privacy_vnext_store.cpp \
    src/subsidy.cpp \
    src/finality_note.cpp \
    src/dag.cpp \
    src/mstimestamp.cpp \
    src/blockprofile.cpp

#### I n n o v a sources

RESOURCES += \
    src/qt/bitcoin.qrc \
    src/qt/res/themes/qdarkstyle/style.qrc

FORMS += \
    src/qt/forms/intro.ui \
    src/qt/forms/coincontroldialog.ui \
    src/qt/forms/sendcoinsdialog.ui \
    src/qt/forms/addressbookpage.ui \
    src/qt/forms/signverifymessagedialog.ui \
    src/qt/forms/aboutdialog.ui \
    src/qt/forms/editaddressdialog.ui \
    src/qt/forms/transactiondescdialog.ui \
    src/qt/forms/overviewpage.ui \
    src/qt/forms/sendcoinsentry.ui \
    src/qt/forms/askpassphrasedialog.ui \
    src/qt/forms/rpcconsole.ui \
    src/qt/forms/optionsdialog.ui \
    src/qt/forms/statisticspage.ui \
    src/qt/forms/blockbrowser.ui \
    src/qt/forms/marketbrowser.ui \
    src/qt/forms/proofofimage.ui \
    src/qt/forms/hyperfile.ui \
    src/qt/forms/termsofuse.ui \
    src/qt/forms/collateralnodemanager.ui \
    src/qt/forms/addeditadrenalinenode.ui \
    src/qt/forms/adrenalinenodeconfigdialog.ui \
    src/qt/forms/multisigaddressentry.ui \
    src/qt/forms/multisiginputentry.ui \
    src/qt/forms/multisigdialog.ui \
    src/qt/forms/managenamespage.ui \
    src/qt/forms/sendmessagesentry.ui \
    src/qt/forms/sendmessagesdialog.ui \
    src/qt/plugins/mrichtexteditor/mrichtextedit.ui

contains(USE_QRCODE, 1) {
HEADERS += src/qt/qrcodedialog.h
SOURCES += src/qt/qrcodedialog.cpp
FORMS += src/qt/forms/qrcodedialog.ui
}

CODECFORTR = UTF-8

# for lrelease/lupdate
# also add new translations to src/qt/bitcoin.qrc under translations/
TRANSLATIONS = $$files(src/qt/locale/bitcoin_*.ts)

isEmpty(QMAKE_LRELEASE) {
    win32:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease.exe
    else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
}
isEmpty(QM_DIR):QM_DIR = $$PWD/src/qt/locale
# automatically build translations, so they can be included in resource file
TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

# "Other files" to show in Qt Creator
OTHER_FILES += \
    doc/*.rst doc/*.txt doc/README README.md res/bitcoin-qt.rc

# platform specific defaults, if not overridden on command line

isEmpty(BOOST_LIB_SUFFIX) {
    macx:BOOST_LIB_SUFFIX =
    windows:BOOST_LIB_SUFFIX = -mgw48-mt-s-1_55
}

isEmpty(BOOST_THREAD_LIB_SUFFIX) {
    BOOST_THREAD_LIB_SUFFIX = $$BOOST_LIB_SUFFIX
}

isEmpty(BDB_LIB_PATH) {
    macx:BDB_LIB_PATH = $$HOMEBREW_PREFIX/opt/berkeley-db@5/lib
}

isEmpty(BDB_LIB_SUFFIX) {
    macx:BDB_LIB_SUFFIX =
}

isEmpty(BDB_INCLUDE_PATH) {
    macx:BDB_INCLUDE_PATH = $$HOMEBREW_PREFIX/opt/berkeley-db@5/include
}

isEmpty(BOOST_LIB_PATH) {
    macx:BOOST_LIB_PATH = $$HOMEBREW_PREFIX/opt/boost/lib
}

isEmpty(BOOST_INCLUDE_PATH) {
    macx:BOOST_INCLUDE_PATH = $$HOMEBREW_PREFIX/opt/boost/include
}

macx:OPENSSL_LIB_PATH = $$HOMEBREW_PREFIX/opt/openssl@3/lib
macx:OPENSSL_INCLUDE_PATH = $$HOMEBREW_PREFIX/opt/openssl@3/include
macx:LIBEVENT_LIB_PATH = $$HOMEBREW_PREFIX/opt/libevent/lib
macx:LIBEVENT_INCLUDE_PATH = $$HOMEBREW_PREFIX/opt/libevent/include
macx:LIBCURL_LIB_PATH = $$HOMEBREW_PREFIX/opt/curl/lib
macx:LIBCURL_INCLUDE_PATH = $$HOMEBREW_PREFIX/opt/curl/include
macx:MINIUPNPC_INCLUDE_PATH = $$HOMEBREW_PREFIX/opt/miniupnpc/include
macx:MINIUPNPC_LIB_PATH = $$HOMEBREW_PREFIX/opt/miniupnpc/lib


windows:DEFINES += WIN32
windows:RC_FILE = src/qt/res/bitcoin-qt.rc

windows:!contains(MINGW_THREAD_BUGFIX, 0) {
    # At least qmake's win32-g++-cross profile is missing the -lmingwthrd
    # thread-safety flag. GCC has -mthreads to enable this, but it doesn't
    # work with static linking. -lmingwthrd must come BEFORE -lmingw, so
    # it is prepended to QMAKE_LIBS_QT_ENTRY.
    # It can be turned off with MINGW_THREAD_BUGFIX=0, just in case it causes
    # any problems on some untested qmake profile now or in the future.
    DEFINES += _MT BOOST_THREAD_PROVIDES_GENERIC_SHARED_MUTEX_ON_WIN
    QMAKE_LIBS_QT_ENTRY = -lmingwthrd $$QMAKE_LIBS_QT_ENTRY
}

!windows:!macx {
    DEFINES += LINUX
    LIBS += -lrt
}

macx:HEADERS += src/qt/macdockiconhandler.h src/qt/macnotificationhandler.h
macx:OBJECTIVE_SOURCES += src/qt/macdockiconhandler.mm src/qt/macnotificationhandler.mm
macx:LIBS += -framework Foundation -framework ApplicationServices -framework AppKit -framework IOKit
macx:DEFINES += MAC_OSX MSG_NOSIGNAL=0
macx:ICON = src/qt/res/icons/innova.icns
macx:TARGET = "Innova"
macx:QMAKE_CFLAGS_THREAD += -pthread
macx:QMAKE_LFLAGS_THREAD += -pthread
macx:QMAKE_MACOSX_DEPLOYMENT_TARGET = 12.0
macx:QMAKE_CXXFLAGS_THREAD += -pthread
macx:QMAKE_RPATHDIR = @executable_path/../Frameworks
macx:QMAKE_CXXFLAGS += -stdlib=libc++ -Wno-deprecated-declarations
# Ad-hoc signing is opt-in for local compatibility only. Release signing and
# notarization are separate packaging steps and must never use --deep.
# Non-fatal: a failed recipe makes make delete the linked binary.
macx:contains(ADHOC_SIGN, 1):QMAKE_POST_LINK += (codesign --force --sign - --timestamp=none $${TARGET}.app || true)


# Set libraries and includes at end, to use platform-defined defaults if not overridden
INCLUDEPATH += $$BOOST_INCLUDE_PATH $$BDB_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH $$LIBEVENT_INCLUDE_PATH $$LIBCURL_INCLUDE_PATH
LIBS += $$join(BOOST_LIB_PATH,,-L,) $$join(BDB_LIB_PATH,,-L,) $$join(OPENSSL_LIB_PATH,,-L,) $$join(QRENCODE_LIB_PATH,,-L,) $$join(LIBEVENT_LIB_PATH,,-L,) $$join(LIBCURL_LIB_PATH,,-L,)
LIBS += -lcurl -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX
LIBS += -lz -levent
LIBS += -lboost_filesystem$$BOOST_LIB_SUFFIX -lboost_program_options$$BOOST_LIB_SUFFIX -lboost_thread$$BOOST_THREAD_LIB_SUFFIX -lboost_chrono$$BOOST_LIB_SUFFIX

# -lgdi32 has to happen after -lcrypto (see  #681)
windows:LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32
windows:LIBS += -lboost_chrono$$BOOST_LIB_SUFFIX
win32:contains(STATIC_LINK, 1) {
    DEFINES += CURL_STATICLIB
    LIBS += -lssh2 -lbcrypt -lcrypt32 -lwldap32 -lbrotlidec -lbrotlicommon -lzstd
    LIBS += -lnghttp2 -lnghttp3 -lngtcp2_crypto_ossl -lngtcp2 -lpsl -lidn2 -lunistring -liconv -lsecur32
    LIBS += -lssl -lcrypto -lws2_32 -lz -lcrypt32
}

contains(RELEASE, 1) {
    !windows:!macx {
        # Linux: turn dynamic linking back on for c/c++ runtime libraries
        LIBS += -Wl,-Bdynamic
    }
}

!windows:!macx:!android:!ios {
     DEFINES += LINUX
     LIBS += -lrt -ldl
 }

system($$QMAKE_LRELEASE -silent $$_PRO_FILE_)

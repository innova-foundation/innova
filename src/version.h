// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

#include "clientversion.h"
#include <string>

//
// client versioning
//

static const int CLIENT_VERSION =
                           1000000 * CLIENT_VERSION_MAJOR
                         +   10000 * CLIENT_VERSION_MINOR
                         +     100 * CLIENT_VERSION_REVISION
                         +       1 * CLIENT_VERSION_BUILD;

extern const std::string CLIENT_NAME;
extern const std::string CLIENT_BUILD;
extern const std::string CLIENT_DATE;
extern const std::string CLIENT_BUILD_COMMIT;
extern const bool CLIENT_BUILD_DIRTY;

//
// database format versioning
//
static const int DATABASE_VERSION = 21212;

//
// network protocol versioning
//

static const int PROTOCOL_VERSION = 52100;

// peers at or above this may exchange Nyx v2 objects (smsg relay only)
static const int NYX_V2_PROTO = 52100;

// v5.2.0.2, the network standard
static const int V52_PROTO_VERSION = 52002;

// intial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 21212;

// disconnect from peers older than this proto version (v5.2.0.2)
static const int MIN_PEER_PROTO_VERSION = 52002;

// Don't forget to change proto in COLLATERAL.h as well!! On Block 1.5m this will be 31005
extern int MIN_MN_PROTO_VERSION;

// nTime field added to CAddress, starting with this version;
// if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 43500; // start sharing node timeinfo with this proto version 43500

#endif

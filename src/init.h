// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include "wallet.h"

extern CWallet* pwalletMain;
void StartShutdown();
/** True once a shutdown has been asked for by any route: SIGTERM/SIGINT, the
 *  stop RPC, or a UI quit. One flag for all of them, so a UI event loop can ask
 *  the same question the core loops already ask. */
bool ShutdownRequested();
void Shutdown(void* parg);
bool AppInit2();
std::string HelpMessage();

#endif

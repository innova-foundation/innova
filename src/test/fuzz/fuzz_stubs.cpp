// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Definitions a standalone fuzz harness needs but which otherwise live only in
// init.cpp. Linking init.cpp would pull the whole daemon into the harness, so
// the few symbols the target actually references are provided here instead.

#include "ui_interface.h"

CClientUIInterface uiInterface;

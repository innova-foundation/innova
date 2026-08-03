// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Symbols the fuzz targets reference that otherwise live only in init.cpp,
// which would pull the whole daemon into the harness.

#include "ui_interface.h"

CClientUIInterface uiInterface;

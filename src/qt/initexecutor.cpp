// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "initexecutor.h"

#include "init.h"

InitExecutor::InitExecutor()
{
    fSuccess = false;
}

bool InitExecutor::success() const
{
    return fSuccess;
}

void InitExecutor::initialize()
{
    fSuccess = AppInit2();
    emit initializeResult(fSuccess);
}

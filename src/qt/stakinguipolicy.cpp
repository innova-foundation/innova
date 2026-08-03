#include "stakinguipolicy.h"

#include <QtGlobal>

namespace StakingUiPolicy
{

int CoreModeForTabIndex(int tabIndex)
{
    return tabIndex >= 0 && tabIndex <= 3 ? tabIndex : -1;
}

bool IsLegacyPrivateTab(int tabIndex)
{
    return tabIndex == 1 || tabIndex == 3;
}

const char* ModeDescriptionSource(int tabIndex)
{
    switch (tabIndex)
    {
    case 0:
        return QT_TRANSLATE_NOOP("StakingPage", "Mode: Transparent Staking");
    case 1:
        return QT_TRANSLATE_NOOP("StakingPage", "Mode: NullStake Private Staking");
    case 2:
        return QT_TRANSLATE_NOOP("StakingPage", "Mode: Cold Staking (Delegated)");
    case 3:
        return QT_TRANSLATE_NOOP("StakingPage", "Mode: Private Cold Staking");
    default:
        return QT_TRANSLATE_NOOP("StakingPage", "Mode: Unknown");
    }
}

} // namespace StakingUiPolicy

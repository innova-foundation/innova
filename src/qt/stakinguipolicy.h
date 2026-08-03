#ifndef INNOVA_QT_STAKINGUIPOLICY_H
#define INNOVA_QT_STAKINGUIPOLICY_H

namespace StakingUiPolicy
{

/** Return the core StakingMode integer for a tab, or -1 when invalid. */
int CoreModeForTabIndex(int tabIndex);

/** True for the two legacy shielded staking tabs. */
bool IsLegacyPrivateTab(int tabIndex);

/** Source text passed through StakingPage::tr() by the widget. */
const char* ModeDescriptionSource(int tabIndex);

} // namespace StakingUiPolicy

#endif // INNOVA_QT_STAKINGUIPOLICY_H

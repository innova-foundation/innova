#ifndef INNOVA_QT_PRIVACYUIPOLICY_H
#define INNOVA_QT_PRIVACYUIPOLICY_H

namespace PrivacyUiPolicy
{

enum class State
{
    LegacyRegtestOnly,
    LegacyQuarantinedPendingVNext,
    VNextScreenRequired
};

struct Decision
{
    bool legacyControlsEnabled;
    State state;
};

/** Whether a legacy (versions 2000--2007) GUI may mutate wallet state. */
Decision EvaluateLegacyControls(bool isRegtest, bool boundaryBActive,
                                bool vnextGuiReady);

} // namespace PrivacyUiPolicy

#endif // INNOVA_QT_PRIVACYUIPOLICY_H

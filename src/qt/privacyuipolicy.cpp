#include "privacyuipolicy.h"

namespace PrivacyUiPolicy
{

Decision EvaluateLegacyControls(bool isRegtest, bool boundaryBActive,
                                bool vnextGuiReady)
{
    if (isRegtest && !boundaryBActive)
        return {true, State::LegacyRegtestOnly};
    if (boundaryBActive && vnextGuiReady)
        return {false, State::VNextScreenRequired};
    return {false, State::LegacyQuarantinedPendingVNext};
}

} // namespace PrivacyUiPolicy

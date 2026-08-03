#include "policytests.h"

#include "../privacyuipolicy.h"
#include "../stakinguipolicy.h"

#include <QString>

void PolicyTests::stakingModeMappings()
{
    QCOMPARE(StakingUiPolicy::CoreModeForTabIndex(0), 0);
    QCOMPARE(StakingUiPolicy::CoreModeForTabIndex(1), 1);
    QCOMPARE(StakingUiPolicy::CoreModeForTabIndex(2), 2);
    QCOMPARE(StakingUiPolicy::CoreModeForTabIndex(3), 3);
    QCOMPARE(StakingUiPolicy::CoreModeForTabIndex(-1), -1);
    QCOMPARE(StakingUiPolicy::CoreModeForTabIndex(4), -1);

    QVERIFY(!StakingUiPolicy::IsLegacyPrivateTab(0));
    QVERIFY(StakingUiPolicy::IsLegacyPrivateTab(1));
    QVERIFY(!StakingUiPolicy::IsLegacyPrivateTab(2));
    QVERIFY(StakingUiPolicy::IsLegacyPrivateTab(3));
    QCOMPARE(QString::fromLatin1(StakingUiPolicy::ModeDescriptionSource(3)),
             QStringLiteral("Mode: Private Cold Staking"));
}

void PolicyTests::privacyAvailability()
{
    PrivacyUiPolicy::Decision decision =
        PrivacyUiPolicy::EvaluateLegacyControls(true, false, false);
    QVERIFY(decision.legacyControlsEnabled);
    QCOMPARE(decision.state, PrivacyUiPolicy::State::LegacyRegtestOnly);

    decision = PrivacyUiPolicy::EvaluateLegacyControls(false, false, false);
    QVERIFY(!decision.legacyControlsEnabled);
    QCOMPARE(decision.state,
             PrivacyUiPolicy::State::LegacyQuarantinedPendingVNext);

    decision = PrivacyUiPolicy::EvaluateLegacyControls(false, true, true);
    QVERIFY(!decision.legacyControlsEnabled);
    QCOMPARE(decision.state, PrivacyUiPolicy::State::VNextScreenRequired);

    decision = PrivacyUiPolicy::EvaluateLegacyControls(true, true, false);
    QVERIFY(!decision.legacyControlsEnabled);
    QCOMPARE(decision.state,
             PrivacyUiPolicy::State::LegacyQuarantinedPendingVNext);
}

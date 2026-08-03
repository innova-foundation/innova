#ifndef INNOVA_QT_POLICYTESTS_H
#define INNOVA_QT_POLICYTESTS_H

#include <QObject>
#include <QtTest>

class PolicyTests : public QObject
{
    Q_OBJECT

private slots:
    void stakingModeMappings();
    void privacyAvailability();
};

#endif // INNOVA_QT_POLICYTESTS_H

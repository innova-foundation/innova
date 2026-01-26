// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_QT_INITEXECUTOR_H
#define INNOVA_QT_INITEXECUTOR_H

#include <QObject>

class InitExecutor : public QObject
{
    Q_OBJECT

public:
    InitExecutor();
    bool success() const;

public slots:
    void initialize();

signals:
    void initializeResult(bool success);

private:
    bool fSuccess;
};

#endif // INNOVA_QT_INITEXECUTOR_H

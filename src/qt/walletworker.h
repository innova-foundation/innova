#ifndef WALLETWORKER_H
#define WALLETWORKER_H

#include <QObject>
#include <QThread>
#include <QString>

class CWallet;
class WalletModel;

/** Worker that executes wallet operations on a background thread.
 *  All methods are slots — call them via signal from the UI thread.
 *  Results are emitted as signals back to the UI thread. */
class WalletWorker : public QObject
{
    Q_OBJECT

public:
    explicit WalletWorker(QObject *parent = 0);
    void setWallet(CWallet *wallet);

public slots:
    /** Shield coins via z_shield RPC. */
    void doShield(const QString& fromAddr, const QString& amount);

    /** Unshield coins via z_unshield RPC. */
    void doUnshield(const QString& fromZAddr, const QString& toAddr, const QString& amount);

    /** Send shielded via z_send RPC. */
    void doSendShielded(const QString& fromAddr, const QString& toAddr, const QString& amount, int privacyMode);

    /** Send transparent via sendtoaddress. */
    void doSendTransparent(const QString& toAddr, const QString& amount);

    /** Execute arbitrary RPC command. */
    void doRPC(const QString& command);

signals:
    /** Emitted when any operation completes. */
    void operationComplete(bool success, const QString& operation, const QString& result);

    /** Emitted for progress updates during long operations. */
    void operationProgress(const QString& operation, const QString& status);

private:
    CWallet *wallet;
    QString executeRPCInternal(const QString& command, QString& errorOut);
};

/** Helper to manage the worker thread lifecycle. */
class WalletThread : public QObject
{
    Q_OBJECT

public:
    WalletThread(CWallet *wallet, QObject *parent = 0);
    ~WalletThread();

    WalletWorker* worker() { return m_worker; }

private:
    QThread *m_thread;
    WalletWorker *m_worker;
};

#endif // WALLETWORKER_H

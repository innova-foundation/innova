#include "walletworker.h"
#include "wallet.h"
#include "init.h"
#include "innovarpc.h"
#include "json/json_spirit_value.h"

#include <sstream>

WalletWorker::WalletWorker(QObject *parent) :
    QObject(parent),
    wallet(0)
{
}

void WalletWorker::setWallet(CWallet *wallet)
{
    this->wallet = wallet;
}

QString WalletWorker::executeRPCInternal(const QString& command, QString& errorOut)
{
    errorOut.clear();
    try {
        std::string cmd = command.toStdString();
        std::vector<std::string> args;

        std::istringstream iss(cmd);
        std::string token;
        while (iss >> token)
        {
            if (!token.empty() && token[0] == '"')
            {
                while (token.back() != '"' || token.size() == 1)
                {
                    std::string next;
                    if (!(iss >> next)) break;
                    token += " " + next;
                }
                if (token.size() >= 2 && token.front() == '"' && token.back() == '"')
                    token = token.substr(1, token.size() - 2);
            }
            args.push_back(token);
        }

        if (args.empty()) { errorOut = "Empty command"; return QString(); }

        std::string method = args[0];
        std::vector<std::string> params(args.begin() + 1, args.end());

        json_spirit::Value result = tableRPC.execute(method, RPCConvertValues(method, params));

        if (result.type() == json_spirit::null_type) return QString();
        if (result.type() == json_spirit::str_type) return QString::fromStdString(result.get_str());
        return QString::fromStdString(json_spirit::write_string(result, true));
    }
    catch (json_spirit::Object& objError)
    {
        try { errorOut = QString::fromStdString(json_spirit::find_value(objError, "message").get_str()); }
        catch (...) { errorOut = "Unknown RPC error"; }
        return QString();
    }
    catch (std::exception& e) { errorOut = QString::fromStdString(e.what()); return QString(); }
}

void WalletWorker::doShield(const QString& fromAddr, const QString& amount)
{
    emit operationProgress("shield", "Generating zero-knowledge proof...");

    QString from = fromAddr.isEmpty() ? "\"*\"" : ("\"" + fromAddr + "\"");
    QString cmd = QString("z_shield %1 %2").arg(from, amount);
    QString error;
    QString result = executeRPCInternal(cmd, error);

    if (!error.isEmpty())
        emit operationComplete(false, "shield", error);
    else
        emit operationComplete(true, "shield", result);
}

void WalletWorker::doUnshield(const QString& fromZAddr, const QString& toAddr, const QString& amount)
{
    emit operationProgress("unshield", "Generating zero-knowledge proof...");

    QString cmd = QString("z_unshield \"%1\" \"%2\" %3").arg(fromZAddr, toAddr, amount);
    QString error;
    QString result = executeRPCInternal(cmd, error);

    if (!error.isEmpty())
        emit operationComplete(false, "unshield", error);
    else
        emit operationComplete(true, "unshield", result);
}

void WalletWorker::doSendShielded(const QString& fromAddr, const QString& toAddr, const QString& amount, int privacyMode)
{
    emit operationProgress("send_shielded", "Creating FCMP++ proof and shielded transaction...");

    QString cmd = QString("z_send \"%1\" \"%2\" %3 %4").arg(fromAddr, toAddr, amount).arg(privacyMode);
    QString error;
    QString result = executeRPCInternal(cmd, error);

    if (!error.isEmpty())
        emit operationComplete(false, "send_shielded", error);
    else
        emit operationComplete(true, "send_shielded", result);
}

void WalletWorker::doSendTransparent(const QString& toAddr, const QString& amount)
{
    emit operationProgress("send", "Creating transaction...");

    QString cmd = QString("sendtoaddress \"%1\" %2").arg(toAddr, amount);
    QString error;
    QString result = executeRPCInternal(cmd, error);

    if (!error.isEmpty())
        emit operationComplete(false, "send", error);
    else
        emit operationComplete(true, "send", result);
}

void WalletWorker::doRPC(const QString& command)
{
    emit operationProgress("rpc", "Executing...");

    QString error;
    QString result = executeRPCInternal(command, error);

    if (!error.isEmpty())
        emit operationComplete(false, "rpc", error);
    else
        emit operationComplete(true, "rpc", result);
}

// === WalletThread ===

WalletThread::WalletThread(CWallet *wallet, QObject *parent) :
    QObject(parent)
{
    m_thread = new QThread(this);
    m_worker = new WalletWorker();
    m_worker->setWallet(wallet);
    m_worker->moveToThread(m_thread);

    // Clean up worker when thread finishes
    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);

    m_thread->start();
}

WalletThread::~WalletThread()
{
    m_thread->quit();
    m_thread->wait(5000);
}

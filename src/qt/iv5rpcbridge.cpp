#include "iv5rpcbridge.h"

#include "innovarpc.h"
#include "main.h"
#include "privacy_vnext/iv5_protocol.h"

#include "json/json_spirit_value.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_reader_template.h"

#include <QObject>
#include <string>
#include <vector>

namespace
{

// The v2008 verbs the privacy surfaces are allowed to reach. Everything the GUI
// can drive is here, so widening the GUI's reach is one edit in one place.
const char* kAllowedMethods[] = {
    "z_iv5transfer",
    "z_shieldall",
    "z_migratetopool",
    "z_getnewiv5address",
    "z_getshieldedinfo",
    "z_rescaniv5",
    "z_createiv5seed",
    "z_exportphrase",
    "z_importphrase",
    "getfinalityinfo",
    "collateralnode",
    NULL
};

bool IsAllowed(const std::string& strMethod)
{
    for (int i = 0; kAllowedMethods[i] != NULL; i++)
        if (strMethod == kAllowedMethods[i])
            return true;
    return false;
}

const json_spirit::Value* Find(const json_spirit::Object& obj, const std::string& key)
{
    for (json_spirit::Object::const_iterator it = obj.begin(); it != obj.end(); ++it)
        if (it->name_ == key)
            return &it->value_;
    return NULL;
}

void ReadInt(const json_spirit::Object& obj, const char* key, int& out)
{
    const json_spirit::Value* v = Find(obj, key);
    if (v == NULL)
        return;
    if (v->type() == json_spirit::int_type)
        out = (int)v->get_int64();
    else if (v->type() == json_spirit::real_type)
        out = (int)v->get_real();
}

void ReadBool(const json_spirit::Object& obj, const char* key, bool& out)
{
    const json_spirit::Value* v = Find(obj, key);
    if (v != NULL && v->type() == json_spirit::bool_type)
        out = v->get_bool();
}

void ReadStr(const json_spirit::Object& obj, const char* key, QString& out)
{
    const json_spirit::Value* v = Find(obj, key);
    if (v != NULL && v->type() == json_spirit::str_type)
        out = QString::fromStdString(v->get_str());
}

void ReadReal(const json_spirit::Object& obj, const char* key, double& out, bool& haveOut)
{
    const json_spirit::Value* v = Find(obj, key);
    if (v == NULL)
        return;
    if (v->type() == json_spirit::real_type)
    {
        out = v->get_real();
        haveOut = true;
    }
    else if (v->type() == json_spirit::int_type)
    {
        out = (double)v->get_int64();
        haveOut = true;
    }
}

// Runs a whitelisted RPC and hands back the parsed reply.
bool Execute(const QString& method, const QStringList& params,
             json_spirit::Value& valueOut, QString& errorOut)
{
    errorOut.clear();

    const std::string strMethod = method.toStdString();
    if (!IsAllowed(strMethod))
    {
        errorOut = QObject::tr("RPC method '%1' is not reachable from the GUI").arg(method);
        return false;
    }

    std::vector<std::string> vParams;
    for (int i = 0; i < params.size(); i++)
        vParams.push_back(params.at(i).toStdString());

    try
    {
        valueOut = tableRPC.execute(strMethod, RPCConvertValues(strMethod, vParams));
        return true;
    }
    catch (json_spirit::Object& objError)
    {
        const json_spirit::Value* v = Find(objError, "message");
        if (v != NULL && v->type() == json_spirit::str_type)
            errorOut = QString::fromStdString(v->get_str());
        else
            errorOut = QObject::tr("the node refused the call without a reason");
        return false;
    }
    catch (std::exception& e)
    {
        errorOut = QString::fromStdString(e.what());
        return false;
    }
}

} // namespace

namespace Iv5Rpc
{

FinalitySnapshot::FinalitySnapshot() :
    nHeight(-1),
    nEpoch(-1),
    nEpochInterval(0),
    nFinalizedHeight(-1),
    nFinalizedEpoch(-1),
    strTier(QObject::tr("unknown")),
    nConsecutiveHardEpochs(0),
    nTransparentVotes(0),
    nPrivateVotes(0),
    nVoters(0),
    fBoundaryAActive(false),
    fBoundaryBActive(false),
    fCommitteeSeated(false),
    nCommitteeSeats(0),
    nCommitteeThresholdM(0),
    nCommitteeTermEpoch(-1),
    nCommitteeTermEpochs(0),
    fHaveNextDraw(false),
    nNextTermEpoch(-1),
    nNextAnchorHeight(-1),
    nNextRegistryRows(0),
    nNextRowsRequired(0),
    fNextSeated(false),
    nCertificates(0),
    nPrivateCertificates(0),
    fPrivateCertificatePresent(false),
    fPendingPrivateCertificatePresent(false),
    nCertificateVersion(0),
    strCertificateSource(QObject::tr("unknown")),
    strPrivatePromotionStatus(QObject::tr("unknown")),
    strEpochStateHealth(QObject::tr("unknown"))
{
}

QString FinalitySnapshot::LaneDescription() const
{
    if (fPrivateCertificatePresent || nPrivateCertificates > 0)
        return QObject::tr("private (committee tally), certificate version %1")
                   .arg(nCertificateVersion);
    if (fPendingPrivateCertificatePresent)
        return QObject::tr("a private certificate is assembled but no block carries it yet");
    if (nCertificates > 0)
        return QObject::tr("transparent (public tally), %1 certificate(s) this epoch")
                   .arg(nCertificates);
    return QObject::tr("none: no certificate for this epoch");
}

PoolSnapshot::PoolSnapshot() :
    fHaveBalance(false),
    dBalance(0.0),
    dUnconfirmed(0.0),
    nNoteCount(0),
    fSeedUnlocked(false),
    nScanGapHeight(-1),
    fHavePoolValue(false),
    dPoolValue(0.0),
    fBoundaryBActive(false),
    fTransactionsAccepted(false),
    fUnshieldRetired(false),
    nUnshieldRetirementHeight(PRIVACY_VNEXT_HEIGHT_UNSET)
{
}

bool PoolSnapshot::UnshieldRetirementScheduled() const
{
    return nUnshieldRetirementHeight != PRIVACY_VNEXT_HEIGHT_UNSET;
}

bool FetchFinality(FinalitySnapshot& out, QString& errorOut)
{
    json_spirit::Value value;
    if (!Execute("getfinalityinfo", QStringList(), value, errorOut))
        return false;
    if (value.type() != json_spirit::obj_type)
    {
        errorOut = QObject::tr("getfinalityinfo did not return an object");
        return false;
    }

    const json_spirit::Object& obj = value.get_obj();
    ReadInt(obj, "height", out.nHeight);
    ReadInt(obj, "epoch", out.nEpoch);
    ReadInt(obj, "epoch_interval", out.nEpochInterval);
    ReadInt(obj, "finalized_height", out.nFinalizedHeight);
    ReadInt(obj, "finalized_epoch", out.nFinalizedEpoch);
    ReadStr(obj, "finalized_hash", out.strFinalizedHash);
    ReadStr(obj, "finality_tier", out.strTier);
    ReadInt(obj, "consecutive_hard_epochs", out.nConsecutiveHardEpochs);
    ReadInt(obj, "transparent_votes", out.nTransparentVotes);
    ReadInt(obj, "private_votes", out.nPrivateVotes);
    ReadInt(obj, "current_epoch_voters", out.nVoters);
    ReadBool(obj, "boundary_a_active", out.fBoundaryAActive);
    ReadBool(obj, "boundary_b_active", out.fBoundaryBActive);
    ReadBool(obj, "committee_seated", out.fCommitteeSeated);
    ReadInt(obj, "committee_seat_count", out.nCommitteeSeats);
    ReadInt(obj, "committee_threshold_m", out.nCommitteeThresholdM);
    ReadInt(obj, "committee_term_epoch", out.nCommitteeTermEpoch);
    ReadInt(obj, "committee_term_epochs", out.nCommitteeTermEpochs);
    ReadStr(obj, "committee_set_hash", out.strCommitteeSetHash);

    const json_spirit::Value* seats = Find(obj, "committee_seats");
    if (seats != NULL && seats->type() == json_spirit::array_type)
    {
        const json_spirit::Array& arr = seats->get_array();
        for (size_t i = 0; i < arr.size(); i++)
            if (arr[i].type() == json_spirit::str_type)
                out.vSeatKeys << QString::fromStdString(arr[i].get_str());
    }
    ReadBool(obj, "private_certificate_present", out.fPrivateCertificatePresent);
    ReadBool(obj, "pending_private_certificate_present",
             out.fPendingPrivateCertificatePresent);
    ReadInt(obj, "tally_certificate_version", out.nCertificateVersion);
    ReadStr(obj, "tally_certificate_source", out.strCertificateSource);
    ReadStr(obj, "private_promotion_status", out.strPrivatePromotionStatus);
    ReadStr(obj, "epoch_state_health", out.strEpochStateHealth);

    // Absent when the draw itself fails, which is not the same as a thin registry:
    // the panel says so rather than showing zero rows.
    const json_spirit::Value* draw = Find(obj, "committee_next_term_draw");
    if (draw != NULL && draw->type() == json_spirit::obj_type)
    {
        const json_spirit::Object& next = draw->get_obj();
        out.fHaveNextDraw = true;
        ReadInt(next, "term_epoch", out.nNextTermEpoch);
        ReadInt(next, "anchor_height", out.nNextAnchorHeight);
        ReadInt(next, "registry_rows", out.nNextRegistryRows);
        ReadInt(next, "rows_required", out.nNextRowsRequired);
        ReadBool(next, "seated", out.fNextSeated);
    }

    const json_spirit::Value* certs = Find(obj, "tally_certificates");
    if (certs != NULL && certs->type() == json_spirit::array_type)
    {
        const json_spirit::Array& arr = certs->get_array();
        out.nCertificates = (int)arr.size();
        for (size_t i = 0; i < arr.size(); i++)
        {
            if (arr[i].type() != json_spirit::obj_type)
                continue;
            bool fPrivate = false;
            ReadBool(arr[i].get_obj(), "private_weight", fPrivate);
            // A v4 note-tally certificate never sets private_weight, so identify
            // it by its version and seated committee instead.
            int nVer = 0;
            ReadInt(arr[i].get_obj(), "version", nVer);
            QString strSetHash;
            ReadStr(arr[i].get_obj(), "committee_set_hash", strSetHash);
            const bool fNoteLane =
                nVer >= 4 && !strSetHash.isEmpty() &&
                strSetHash.count(QChar('0')) != strSetHash.size();
            if (fPrivate || fNoteLane)
            {
                out.nPrivateCertificates++;
                if (nVer > out.nCertificateVersion)
                    out.nCertificateVersion = nVer;
            }
        }
    }
    return true;
}

bool FetchPool(PoolSnapshot& out, QString& errorOut)
{
    json_spirit::Value value;
    if (!Execute("z_getshieldedinfo", QStringList(), value, errorOut))
        return false;
    if (value.type() != json_spirit::obj_type)
    {
        errorOut = QObject::tr("z_getshieldedinfo did not return an object");
        return false;
    }

    const json_spirit::Object& obj = value.get_obj();
    ReadReal(obj, "privacy_vnext_balance", out.dBalance, out.fHaveBalance);
    bool fHaveUnconfirmed = false;
    ReadReal(obj, "privacy_vnext_unconfirmed_balance", out.dUnconfirmed, fHaveUnconfirmed);
    ReadInt(obj, "privacy_vnext_note_count", out.nNoteCount);
    ReadBool(obj, "privacy_vnext_seed_unlocked", out.fSeedUnlocked);
    ReadInt(obj, "privacy_vnext_scan_gap_height", out.nScanGapHeight);
    ReadReal(obj, "privacy_vnext_pool_value", out.dPoolValue, out.fHavePoolValue);
    ReadBool(obj, "boundary_b_active", out.fBoundaryBActive);
    ReadBool(obj, "privacy_vnext_transactions_accepted", out.fTransactionsAccepted);
    ReadBool(obj, "privacy_vnext_fee_note_active", out.fUnshieldRetired);
    ReadInt(obj, "privacy_vnext_fee_note_height", out.nUnshieldRetirementHeight);
    return true;
}

bool Call(const QString& method, const QStringList& params,
          QString& resultOut, QString& errorOut)
{
    json_spirit::Value value;
    if (!Execute(method, params, value, errorOut))
        return false;

    if (value.type() == json_spirit::null_type)
        resultOut.clear();
    else if (value.type() == json_spirit::str_type)
        resultOut = QString::fromStdString(value.get_str());
    else
        resultOut = QString::fromStdString(json_spirit::write_string(value, true));
    return true;
}

bool ReadField(const QString& jsonObject, const QString& key, QString& valueOut)
{
    const std::string strJson = jsonObject.toStdString();
    json_spirit::Value value;
    if (!json_spirit::read_string(strJson, value))
        return false;
    if (value.type() != json_spirit::obj_type)
        return false;
    const json_spirit::Value* v = Find(value.get_obj(), key.toStdString());
    if (v == NULL)
        return false;
    if (v->type() == json_spirit::str_type)
        valueOut = QString::fromStdString(v->get_str());
    else
        valueOut = QString::fromStdString(json_spirit::write_string(*v, false));
    return true;
}

bool MaskDisclosesSender(int nMask)
{
    return (nMask & (int)iv5::DISCLOSURE_HIDE_SENDER) == 0;
}

bool MaskDisclosesReceiver(int nMask)
{
    return (nMask & (int)iv5::DISCLOSURE_HIDE_RECEIVER) == 0;
}

bool MaskDisclosesAmount(int nMask)
{
    return (nMask & (int)iv5::DISCLOSURE_HIDE_AMOUNT) == 0;
}

QString MaskTitle(int nMask)
{
    QStringList published;
    if (MaskDisclosesSender(nMask))
        published << QObject::tr("sender");
    if (MaskDisclosesReceiver(nMask))
        published << QObject::tr("recipient");
    if (MaskDisclosesAmount(nMask))
        published << QObject::tr("amount");

    if (published.isEmpty())
        return QObject::tr("%1 - publish nothing").arg(nMask);
    if (published.size() == 3)
        return QObject::tr("%1 - publish everything (sender, recipient, amount)").arg(nMask);
    return QObject::tr("%1 - publish %2").arg(nMask).arg(published.join(QObject::tr(" and ")));
}

QString MaskDetail(int nMask)
{
    return QObject::tr("Sender: %1    Recipient: %2    Amount: %3")
        .arg(MaskDisclosesSender(nMask) ? QObject::tr("published on chain")
                                        : QObject::tr("hidden"))
        .arg(MaskDisclosesReceiver(nMask) ? QObject::tr("published on chain")
                                          : QObject::tr("hidden"))
        .arg(MaskDisclosesAmount(nMask) ? QObject::tr("published on chain")
                                        : QObject::tr("hidden"));
}

} // namespace Iv5Rpc

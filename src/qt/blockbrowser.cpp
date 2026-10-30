#include "blockbrowser.h"
#include "ui_blockbrowser.h"
#include "main.h"
#include "wallet.h"
#include "base58.h"
#include "clientmodel.h"
#include "innovarpc.h"
#include "transactionrecord.h"

#include <cmath>
#include <sstream>
#include <string>
static const CBlockIndex* lookupBlockIndex(int Height)
{
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(uint256(getBlockHash(Height)));
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

double getBlockHardness(int height)
{
    LOCK(cs_main);
    const CBlockIndex* blockindex = getBlockIndex(height);
    if (!blockindex)
        return 0;

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

int getBlockHashrate(int height)
{
    if (height <= 1)
        return 0;

    LOCK(cs_main);
    double timeDiff = getBlockTime(height) - getBlockTime(1);
    double timePerBlock = timeDiff / height;
    if (!std::isfinite(timePerBlock) || timePerBlock <= 0)
        return 0;

    return (boost::int64_t)(((double)getBlockHardness(height) * pow(2.0, 32)) / timePerBlock);
}

const CBlockIndex* getBlockIndex(int height)
{
    LOCK(cs_main);
    return lookupBlockIndex(height);
}

std::string getBlockHash(int Height)
{
    LOCK(cs_main);
    if (!pindexBest || Height > pindexBest->nHeight) { return "00000d5dbbda01621cfc16bbc1f9bf3264d641a5dbf0de89fd0182c2c4828fcd"; }
    if(Height < 0) { return "00000d5dbbda01621cfc16bbc1f9bf3264d641a5dbf0de89fd0182c2c4828fcd"; }
    if (Height > nBestHeight)
        return "00000d5dbbda01621cfc16bbc1f9bf3264d641a5dbf0de89fd0182c2c4828fcd";

    // Use O(1) indexed lookup instead of O(n) pprev walk
    CBlockIndex* pblockindex = FindBlockByHeight(Height);
    if (!pblockindex || !pblockindex->phashBlock)
        return "00000d5dbbda01621cfc16bbc1f9bf3264d641a5dbf0de89fd0182c2c4828fcd";
    return pblockindex->phashBlock->GetHex();
}

int getBlockTime(int Height)
{
    LOCK(cs_main);
    const CBlockIndex* pblockindex = lookupBlockIndex(Height);
    return pblockindex ? pblockindex->nTime : 0;
}

std::string getBlockMerkle(int Height)
{
    LOCK(cs_main);
    const CBlockIndex* pblockindex = lookupBlockIndex(Height);
    return pblockindex ? pblockindex->hashMerkleRoot.ToString().substr(0,10) : std::string();
}

int getBlocknBits(int Height)
{
    LOCK(cs_main);
    const CBlockIndex* pblockindex = lookupBlockIndex(Height);
    return pblockindex ? pblockindex->nBits : 0;
}

int getBlockNonce(int Height)
{
    LOCK(cs_main);
    const CBlockIndex* pblockindex = lookupBlockIndex(Height);
    return pblockindex ? pblockindex->nNonce : 0;
}

std::string getBlockDebug(int Height)
{
    LOCK(cs_main);
    const CBlockIndex* pblockindex = lookupBlockIndex(Height);
    return pblockindex ? pblockindex->ToString() : std::string();
}

int blocksInPastHours(int hours)
{
    LOCK(cs_main);
    if (!pindexBest)
        return 0;

    int wayback = hours * 3600;
    int height = pindexBest->nHeight;
    int heightHour = height;
    int utime = (int)time(NULL);
    int target = utime - wayback;

    // Limit iterations to prevent unbounded loop on UI thread
    int maxIter = std::min(height, 50000);
    for (int i = 0; i < maxIter; i++)
    {
        if (heightHour <= 0)
            return height;
        if (getBlockTime(heightHour) < target)
            return height - heightHour;
        heightHour--;
    }

    return height - heightHour;
}

double getTxTotalValue(std::string txid)
{
    uint256 hash;
    hash.SetHex(txid);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock))
        return 1000;

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;

    double value = 0;
    double buffer = 0;
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];

        buffer = value + convertCoins(txout.nValue);
        value = buffer;
    }

    return value;
}

double convertCoins(int64_t amount)
{
    return (double)amount / (double)COIN;
}

std::string getOutputs(std::string txid)
{
    uint256 hash;
    hash.SetHex(txid);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock))
        return "None";

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;

    std::string str = "";
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
        CTxDestination source;
        ExtractDestination(txout.scriptPubKey, source);
        CBitcoinAddress addressSource(source);
        std::string lol7 = addressSource.ToString();
        double buffer = convertCoins(txout.nValue);
        std::string amount = boost::to_string(buffer);
        str.append(lol7);
        str.append(": ");
        str.append(amount);
        str.append(" INN");
        str.append("\n");
    }

    return str;
}

std::string getInputs(std::string txid)
{
    uint256 hash;
    hash.SetHex(txid);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock))
        return "None";

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;

    std::string str = "";
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        uint256 hash;
        const CTxIn& vin = tx.vin[i];
        hash.SetHex(vin.prevout.hash.ToString());
        CTransaction wtxPrev;
        uint256 hashBlock = 0;
        if (!GetTransaction(hash, wtxPrev, hashBlock))
             return "None";

        if (vin.prevout.n >= wtxPrev.vout.size())
            continue;

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << wtxPrev;

        CTxDestination source;
        ExtractDestination(wtxPrev.vout[vin.prevout.n].scriptPubKey, source);
        CBitcoinAddress addressSource(source);
        std::string lol6 = addressSource.ToString();
        double buffer = convertCoins(wtxPrev.vout[vin.prevout.n].nValue);
        std::string amount = boost::to_string(buffer);
        str.append(lol6);
        str.append(": ");
        str.append(amount);
        str.append("INN");
        str.append("\n");
    }

    return str;
}

double getTxFees(std::string txid)
{
    uint256 hash;
    hash.SetHex(txid);


    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock))
        return 51;

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;

    double value = 0;
    double buffer = 0;
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];

        buffer = value + convertCoins(txout.nValue);
        value = buffer;
    }

    double value0 = 0;
    double buffer0 = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        uint256 hash0;
        const CTxIn& vin = tx.vin[i];
        hash0.SetHex(vin.prevout.hash.ToString());
        CTransaction wtxPrev;
        uint256 hashBlock0 = 0;
        if (!GetTransaction(hash0, wtxPrev, hashBlock0))
             return 0;
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        if (vin.prevout.n >= wtxPrev.vout.size())
            continue;
        ssTx << wtxPrev;
        buffer0 = value0 + convertCoins(wtxPrev.vout[vin.prevout.n].nValue);
        value0 = buffer0;
    }

    return value0 - value;
}


BlockBrowser::BlockBrowser(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::BlockBrowser)
{
    ui->setupUi(this);

    setFixedSize(400, 420);

    connect(ui->blockButton, SIGNAL(pressed()), this, SLOT(blockClicked()));
    connect(ui->txButton, SIGNAL(pressed()), this, SLOT(txClicked()));
}

void BlockBrowser::updateExplorer(bool block)
{
    if(block)
    {
        ui->heightLabel->show();
        ui->heightLabel_2->show();
        ui->hashLabel->show();
        ui->hashBox->show();
        ui->merkleLabel->show();
        ui->merkleBox->show();
        ui->nonceLabel->show();
        ui->nonceBox->show();
        ui->bitsLabel->show();
        ui->bitsBox->show();
        ui->timeLabel->show();
        ui->timeBox->show();
        ui->hardLabel->show();
        ui->hardBox->show();;
        ui->pawLabel->show();
        ui->pawBox->show();
        LOCK(cs_main);
        if (!pindexBest)
            return;
        int height = ui->heightBox->value();
        if (height > pindexBest->nHeight)
        {
            ui->heightBox->setValue(pindexBest->nHeight);
            height = pindexBest->nHeight;
        }
        int Pawrate = getBlockHashrate(height);
        double Pawrate2 = 0.000;
        Pawrate2 = ((double)Pawrate / 1000);
        std::string hash = getBlockHash(height);
        std::string merkle = getBlockMerkle(height);
        int nBits = getBlocknBits(height);
        int nNonce = getBlockNonce(height);
        int atime = getBlockTime(height);
        double hardness = getBlockHardness(height);
        QString QHeight = QString::number(height);
        QString QHash = QString::fromUtf8(hash.c_str());
        QString QMerkle = QString::fromUtf8(merkle.c_str());
        QString QBits = QString::number(nBits);
        QString QNonce = QString::number(nNonce);
        QString QTime = QString::number(atime);
        QString QHardness = QString::number(hardness, 'f', 6);
        QString QPawrate = QString::number(Pawrate2, 'f', 3);
        ui->heightLabel->setText(QHeight);
        ui->hashBox->setText(QHash);
        ui->merkleBox->setText(QMerkle);
        ui->bitsBox->setText(QBits);
        ui->nonceBox->setText(QNonce);
        ui->timeBox->setText(QTime);
        ui->hardBox->setText(QHardness);
        ui->pawBox->setText(QPawrate + " KH/s");
    }

    if(block == false) {
        ui->txID->show();
        ui->txLabel->show();
        ui->valueLabel->show();
        ui->valueBox->show();
        ui->inputLabel->show();
        ui->inputBox->show();
        ui->outputLabel->show();
        ui->outputBox->show();
        ui->feesLabel->show();
        ui->feesBox->show();
        std::string txid = ui->txBox->text().toUtf8().constData();
        double value = getTxTotalValue(txid);
        double fees = getTxFees(txid);
        std::string outputs = getOutputs(txid);
        std::string inputs = getInputs(txid);
        QString QValue = QString::number(value, 'f', 6);
        QString QID = QString::fromUtf8(txid.c_str());
        QString QOutputs = QString::fromUtf8(outputs.c_str());
        QString QInputs = QString::fromUtf8(inputs.c_str());
        QString QFees = QString::number(fees, 'f', 6);
        ui->valueBox->setText(QValue + " INN");
        ui->txID->setText(QID);
        ui->outputBox->setText(QOutputs);
        ui->inputBox->setText(QInputs);
        ui->feesBox->setText(QFees + " INN");
    }
}


void BlockBrowser::txClicked()
{
    updateExplorer(false);
}

void BlockBrowser::blockClicked()
{
    updateExplorer(true);
}

void BlockBrowser::setModel(ClientModel *model)
{
    this->model = model;
}

BlockBrowser::~BlockBrowser()
{
    delete ui;
}

#include <boost/test/unit_test.hpp>

#include "../cn_payee.h"
#include "../subsidy.h"
#include "../txdb.h"
#include "../hash.h"

#include <memory>
#include <limits>

BOOST_AUTO_TEST_SUITE(cn_payee_tests)

namespace {
struct Heights
{
    bool reg = fRegTest, test = fTestNet;
    int height = nRegtestCNPayeeHeight;
    Heights() { fRegTest = true; fTestNet = false; nRegtestCNPayeeHeight = 200; }
    ~Heights() { fRegTest = reg; fTestNet = test; nRegtestCNPayeeHeight = height; }
};

CScript Payee(unsigned int n) { return GetScriptForDestination(CKeyID(uint160(n))); }

struct Node
{
    CKey collateralKey, nodeKey;
    CTransaction collateral;
    Node(unsigned int n)
    {
        collateralKey.MakeNewKey(true);
        nodeKey.MakeNewKey(true);
        collateral.vin.push_back(CTxIn(COutPoint(uint256(n), 0)));
        collateral.vout.push_back(CTxOut(25000 * COIN, Script()));
    }
    CScript Script() const { return GetScriptForDestination(collateralKey.GetPubKey().GetID()); }
    COutPoint Point() const { return COutPoint(collateral.GetHash(), 0); }
    CTransaction Funding(uint64_t sequence = 1) const
    {
        CTransaction tx;
        tx.vin.push_back(CTxIn(COutPoint(collateral.GetHash(), (unsigned int)sequence)));
        return tx;
    }
    CCNRegistration Record(const CTransaction& tx, uint64_t sequence) const
    {
        CCNRegistration record;
        record.collateral = Point();
        record.pubkey = nodeKey.GetPubKey();
        record.inputsHash = CNRegistrationInputsHash(tx);
        record.sequence = sequence;
        BOOST_REQUIRE(collateralKey.SignCompact(CNRegistrationHash(record), record.signature));
        return record;
    }
    CCNRegistration Record(uint64_t sequence = 1) const { return Record(Funding(sequence), sequence); }
    CTransaction Registration(uint64_t sequence = 1) const
    {
        CTransaction tx = Funding(sequence);
        tx.vout.push_back(CTxOut(0, CNRegistrationScript(Record(tx, sequence))));
        return tx;
    }
};

struct Chain
{
    std::vector<std::unique_ptr<CBlockIndex> > blocks;
    ~Chain()
    {
        for (auto it = blocks.rbegin(); it != blocks.rend(); ++it)
        {
            BlockIndexLeavesErase(it->get());
            mapBlockIndex.erase((*it)->GetBlockHash());
        }
    }
    CBlockIndex* Add(CBlockIndex* prev)
    {
        CBlock block;
        block.hashPrevBlock = prev ? prev->GetBlockHash() : uint256();
        block.nTime = 1400000000;
        block.nNonce = 900000 + blocks.size();
        const uint256 hash = block.GetHash();
        std::unique_ptr<CBlockIndex> p(new CBlockIndex(0, 0, block));
        p->pprev = prev;
        p->nHeight = prev ? prev->nHeight + 1 : 0;
        const auto inserted = mapBlockIndex.insert(std::make_pair(hash, p.get()));
        BOOST_REQUIRE(inserted.second);
        p->phashBlock = &inserted.first->first;
        p->BuildSkip();
        BlockIndexLeavesInsert(p.get());
        blocks.push_back(std::move(p));
        return blocks.back().get();
    }
};
}

BOOST_AUTO_TEST_CASE(network_activation_and_legacy_boundary)
{
    Heights heights;
    fRegTest = false;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_CN_PAYEE, 8790000);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_MERGESET, 8547840);
    BOOST_CHECK(!IsCNPayeeActiveAtHeight(8789999));
    BOOST_CHECK(IsCNPayeeActiveAtHeight(8790000));
    CTransaction empty;
    BOOST_CHECK(CheckCNPayeePayment(8789999, empty, Payee(1), COIN, {}));
    BOOST_CHECK(!CheckCNPayeePayment(8790000, empty, Payee(1), COIN, {}));
    fTestNet = true;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_CN_PAYEE, PRIVACY_VNEXT_HEIGHT_UNSET);
    BOOST_CHECK(!IsCNPayeeActiveAtHeight(PRIVACY_VNEXT_HEIGHT_UNSET));
    fRegTest = true;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_CN_PAYEE, 200);
    BOOST_CHECK(!IsCNPayeeActiveAtHeight(199));
    BOOST_CHECK(IsCNPayeeActiveAtHeight(200));
}

BOOST_AUTO_TEST_CASE(independent_derivations_and_score_agree)
{
    CCNPayeeState first, second;
    first.hashTip = second.hashTip = uint256(123);
    std::vector<Node> nodes;
    std::vector<CTransaction> registrations;
    for (unsigned int i = 1; i <= 9; ++i)
    {
        nodes.emplace_back(i);
        registrations.push_back(nodes.back().Registration());
        ApplyCNPayeeTx(first, nodes.back().collateral, 10);
        ApplyCNPayeeTx(first, registrations.back(), 20);
    }
    for (int i = 8; i >= 0; --i)
    {
        ApplyCNPayeeTx(second, nodes[i].collateral, 10);
        ApplyCNPayeeTx(second, registrations[i], 20);
    }
    CScript a, b, expected;
    BOOST_REQUIRE(SelectCNPayee(first, 120, a));
    BOOST_REQUIRE(SelectCNPayee(second, 120, b));
    BOOST_CHECK(a == b);
    uint256 best = ~uint256(0);
    for (const auto& coin : second.coins)
    {
        CHashWriter writer(SER_GETHASH, 0);
        writer << second.hashTip << coin.first;
        const uint256 score = writer.GetHash();
        if (score < best) { best = score; expected = coin.second.script; }
    }
    BOOST_CHECK(a == expected);
}

BOOST_AUTO_TEST_CASE(registration_and_both_confirmation_depths_are_required)
{
    Node node(1);
    CCNPayeeState state;
    ApplyCNPayeeTx(state, node.collateral, 50);
    CScript payee;
    BOOST_CHECK(!SelectCNPayee(state, 1000, payee));
    BOOST_CHECK(CheckCNRegistrationTx(state, node.Registration()));
    ApplyCNPayeeTx(state, node.Registration(), 70);
    BOOST_CHECK(!SelectCNPayee(state, 149, payee));
    BOOST_CHECK(!SelectCNPayee(state, 169, payee));
    BOOST_REQUIRE(SelectCNPayee(state, 170, payee));
    BOOST_CHECK(payee == node.Script());
    state.coins[node.Point()].height = 80;
    BOOST_CHECK(!SelectCNPayee(state, 179, payee));
    BOOST_CHECK(SelectCNPayee(state, 180, payee));
}

BOOST_AUTO_TEST_CASE(forgery_wrong_amount_and_malformed_records_are_refused)
{
    Node node(2), attacker(3);
    CCNPayeeState state;
    ApplyCNPayeeTx(state, node.collateral, 10);
    CCNRegistration record = node.Record(), decoded;
    BOOST_CHECK(DecodeCNRegistration(CNRegistrationScript(record), decoded) == CN_REG_VALID);
    BOOST_CHECK(VerifyCNRegistration(decoded, node.Script(), node.Funding()));
    BOOST_CHECK(!VerifyCNRegistration(decoded, attacker.Script(), node.Funding()));
    record.pubkey = attacker.nodeKey.GetPubKey();
    BOOST_CHECK(!VerifyCNRegistration(record, node.Script(), node.Funding()));
    CTransaction forged = node.Registration();
    forged.vout[0].scriptPubKey = CNRegistrationScript(record);
    BOOST_CHECK(!CheckCNRegistrationTx(state, forged));
    ApplyCNPayeeTx(state, forged, 20);
    CScript payee;
    BOOST_CHECK(!SelectCNPayee(state, 1000, payee));
    record = node.Record();
    record.collateral.n++;
    BOOST_CHECK(!VerifyCNRegistration(record, node.Script(), node.Funding()));
    record = node.Record();
    record.version++;
    BOOST_CHECK(DecodeCNRegistration(CNRegistrationScript(record), decoded) == CN_REG_INVALID);
    BOOST_CHECK(DecodeCNRegistration(CNRegistrationScript(node.Record()) << OP_0, decoded) == CN_REG_INVALID);
    record = node.Record();
    record.signature.resize(64);
    BOOST_CHECK(DecodeCNRegistration(CNRegistrationScript(record), decoded) == CN_REG_INVALID);
    CDataStream shortKey(SER_NETWORK, 0);
    record = node.Record();
    shortKey << uint32_t(0x524e4349) << record.version << record.collateral
             << std::vector<unsigned char>(1, 2) << record.inputsHash << record.sequence << record.signature;
    BOOST_CHECK(DecodeCNRegistration(CScript() << OP_RETURN <<
        std::vector<unsigned char>(shortKey.begin(), shortKey.end()), decoded) == CN_REG_INVALID);
    Node small(4);
    small.collateral.vout[0].nValue--;
    ApplyCNPayeeTx(state, small.collateral, 10);
    BOOST_CHECK(!CheckCNRegistrationTx(state, small.Registration()));
    ApplyCNPayeeTx(state, small.Registration(), 20);
    BOOST_CHECK(!SelectCNPayee(state, 1000, payee));
}

BOOST_AUTO_TEST_CASE(latest_valid_registration_wins_and_spend_removes_eligibility)
{
    Node node(5), replacement(6);
    CCNPayeeState state;
    ApplyCNPayeeTx(state, node.collateral, 10);
    ApplyCNPayeeTx(state, node.Registration(), 20);
    CScript payee;
    BOOST_REQUIRE(SelectCNPayee(state, 120, payee));
    node.nodeKey = replacement.nodeKey;
    BOOST_REQUIRE(CheckCNRegistrationTx(state, node.Registration(2)));
    ApplyCNPayeeTx(state, node.Registration(2), 121);
    BOOST_CHECK(state.coins[node.Point()].pubkey == replacement.nodeKey.GetPubKey());
    BOOST_CHECK(!SelectCNPayee(state, 220, payee));
    BOOST_CHECK(SelectCNPayee(state, 221, payee));
    CCNRegistration forged = node.Record(3);
    BOOST_REQUIRE(replacement.collateralKey.SignCompact(CNRegistrationHash(forged), forged.signature));
    CTransaction invalid = node.Registration(3);
    invalid.vout[0].scriptPubKey = CNRegistrationScript(forged);
    ApplyCNPayeeTx(state, invalid, 222);
    BOOST_CHECK_EQUAL(state.coins[node.Point()].registrationHeight, 121);
    CTransaction spend;
    spend.vin.push_back(CTxIn(node.Point()));
    spend.vout.push_back(CTxOut(COIN, Payee(2)));
    spend.vout.push_back(CTxOut(0, CNRegistrationScript(node.Record())));
    BOOST_CHECK(!CheckCNRegistrationTx(state, spend));
    ApplyCNPayeeTx(state, spend, 223);
    ApplyCNPayeeTx(state, node.Registration(), 224);
    BOOST_CHECK(state.coins.empty());
    BOOST_CHECK(!SelectCNPayee(state, 1000, payee));
    BOOST_CHECK(payee.empty());
}

BOOST_AUTO_TEST_CASE(replayed_payload_does_not_reset_confirmation_depth)
{
    Node node(10);
    CCNPayeeState state;
    ApplyCNPayeeTx(state, node.collateral, 10);
    const CTransaction registration = node.Registration();
    BOOST_REQUIRE(CheckCNRegistrationTx(state, registration));
    ApplyCNPayeeTx(state, registration, 20);
    const CNPayeeCoins saved = state.coins;
    BOOST_CHECK_EQUAL(state.coins[node.Point()].sequence, 1U);
    BOOST_CHECK(!CheckCNRegistrationTx(state, registration));
    CCNPayeeUndo undo;
    ApplyCNPayeeTx(state, registration, 119, &undo);
    BOOST_CHECK(state.coins == saved);
    BOOST_CHECK(undo.previous.empty());
    CScript payee;
    BOOST_REQUIRE(SelectCNPayee(state, 120, payee));
    BOOST_CHECK(payee == node.Script());
}

BOOST_AUTO_TEST_CASE(copied_payload_with_foreign_funding_is_refused)
{
    Node node(11), attacker(12);
    CCNPayeeState state;
    ApplyCNPayeeTx(state, node.collateral, 10);
    CTransaction registration = node.Registration();
    CCNRegistration record;
    BOOST_REQUIRE(DecodeCNRegistration(registration.vout[0].scriptPubKey, record) == CN_REG_VALID);
    CTransaction copied = registration;
    copied.vin = attacker.Funding().vin;
    BOOST_CHECK(!VerifyCNRegistration(record, node.Script(), copied));
    BOOST_CHECK(!CheckCNRegistrationTx(state, copied));
    const CNPayeeCoins unregistered = state.coins;
    ApplyCNPayeeTx(state, copied, 19);
    BOOST_CHECK(state.coins == unregistered);
    BOOST_REQUIRE(CheckCNRegistrationTx(state, registration));
    ApplyCNPayeeTx(state, registration, 20);
    const CNPayeeCoins confirmed = state.coins;
    BOOST_CHECK(!CheckCNRegistrationTx(state, copied));
    ApplyCNPayeeTx(state, copied, 120);
    BOOST_CHECK(state.coins == confirmed);

    // Rebinding needs the collateral owner's signature.
    record.inputsHash = CNRegistrationInputsHash(copied);
    copied.vout[0].scriptPubKey = CNRegistrationScript(record);
    BOOST_CHECK(!VerifyCNRegistration(record, node.Script(), copied));
    record.sequence = 2;
    BOOST_REQUIRE(attacker.collateralKey.SignCompact(CNRegistrationHash(record), record.signature));
    copied.vout[0].scriptPubKey = CNRegistrationScript(record);
    BOOST_CHECK(!CheckCNRegistrationTx(state, copied));
    ApplyCNPayeeTx(state, copied, 121);
    BOOST_CHECK(state.coins == confirmed);
}

BOOST_AUTO_TEST_CASE(stale_sequence_with_new_funding_cannot_replace_the_active_key)
{
    Node node(13), replacement(14);
    const CKey originalKey = node.nodeKey;
    CCNPayeeState state;
    ApplyCNPayeeTx(state, node.collateral, 10);
    const CTransaction original = node.Registration();
    ApplyCNPayeeTx(state, original, 20);
    node.nodeKey = replacement.nodeKey;
    const CTransaction current = node.Registration(3);
    BOOST_REQUIRE(CheckCNRegistrationTx(state, current));
    ApplyCNPayeeTx(state, current, 30);
    const CNPayeeCoins saved = state.coins;
    BOOST_CHECK_EQUAL(state.coins[node.Point()].sequence, 3U);

    node.nodeKey = originalKey;
    for (uint64_t sequence : {uint64_t(1), uint64_t(2), uint64_t(3)})
    {
        CTransaction stale = node.Funding(4);
        const CCNRegistration record = node.Record(stale, sequence);
        stale.vout.push_back(CTxOut(0, CNRegistrationScript(record)));
        BOOST_REQUIRE(VerifyCNRegistration(record, node.Script(), stale));
        BOOST_CHECK(!CheckCNRegistrationTx(state, stale));
        CCNPayeeUndo undo;
        ApplyCNPayeeTx(state, stale, 130, &undo);
        BOOST_CHECK(state.coins == saved);
        BOOST_CHECK(undo.previous.empty());
    }
    BOOST_CHECK(!CheckCNRegistrationTx(state, original));
    ApplyCNPayeeTx(state, original, 131);
    BOOST_CHECK(state.coins == saved);
    const CTransaction next = node.Registration(4);
    BOOST_REQUIRE(CheckCNRegistrationTx(state, next));
    ApplyCNPayeeTx(state, next, 132);
    BOOST_CHECK_EQUAL(state.coins[node.Point()].sequence, 4U);
    BOOST_CHECK_EQUAL(state.coins[node.Point()].registrationHeight, 132);
    BOOST_CHECK(state.coins[node.Point()].pubkey == originalKey.GetPubKey());
}

BOOST_AUTO_TEST_CASE(sequence_survives_serialization_without_wrapping)
{
    Node node(15);
    CCNPayeeState state;
    ApplyCNPayeeTx(state, node.collateral, 10);
    CTransaction tx = node.Funding();
    const CCNRegistration record = node.Record(tx, std::numeric_limits<uint64_t>::max());
    tx.vout.push_back(CTxOut(0, CNRegistrationScript(record)));
    BOOST_REQUIRE(CheckCNRegistrationTx(state, tx));
    ApplyCNPayeeTx(state, tx, 20);
    CDataStream bytes(SER_DISK, 0);
    bytes << state;
    CCNPayeeState restored;
    bytes >> restored;
    BOOST_CHECK(restored.coins == state.coins);
    BOOST_CHECK(!CheckCNRegistrationTx(restored, tx));
    const CTransaction wrapped = node.Registration();
    BOOST_CHECK(!CheckCNRegistrationTx(restored, wrapped));
    ApplyCNPayeeTx(restored, wrapped, 120);
    BOOST_CHECK(restored.coins == state.coins);
}

BOOST_AUTO_TEST_CASE(input_commitment_and_sequence_are_signed)
{
    Node node(16);
    CTransaction tx = node.Funding();
    tx.vin.push_back(CTxIn(COutPoint(uint256(999), 7)));
    CCNRegistration record = node.Record(tx, 1);
    BOOST_REQUIRE(VerifyCNRegistration(record, node.Script(), tx));
    CTransaction changed = tx;
    changed.vin[0].prevout.n++;
    BOOST_CHECK(!VerifyCNRegistration(record, node.Script(), changed));
    changed = tx;
    std::swap(changed.vin[0], changed.vin[1]);
    BOOST_CHECK(!VerifyCNRegistration(record, node.Script(), changed));
    changed = tx;
    changed.vin.pop_back();
    BOOST_CHECK(!VerifyCNRegistration(record, node.Script(), changed));
    changed.vin.clear();
    BOOST_CHECK(!VerifyCNRegistration(record, node.Script(), changed));
    record.sequence++;
    BOOST_CHECK(!VerifyCNRegistration(record, node.Script(), tx));

    record = node.Record(tx, 0);
    CCNRegistration decoded;
    BOOST_CHECK(!VerifyCNRegistration(record, node.Script(), tx));
    BOOST_CHECK(DecodeCNRegistration(CNRegistrationScript(record), decoded) == CN_REG_INVALID);
    CDataStream legacy(SER_NETWORK, 0);
    record = node.Record(tx, 1);
    legacy << uint32_t(0x524e4349) << uint8_t(1) << record.collateral << record.pubkey << record.signature;
    BOOST_CHECK(DecodeCNRegistration(CScript() << OP_RETURN <<
        std::vector<unsigned char>(legacy.begin(), legacy.end()), decoded) == CN_REG_INVALID);
}

BOOST_AUTO_TEST_CASE(repeated_sequence_in_one_transaction_is_refused)
{
    Node node(17);
    CCNPayeeState state;
    ApplyCNPayeeTx(state, node.collateral, 10);
    CTransaction tx = node.Registration();
    tx.vout.push_back(tx.vout[0]);
    BOOST_CHECK(!CheckCNRegistrationTx(state, tx));
    ApplyCNPayeeTx(state, tx, 20);
    BOOST_CHECK_EQUAL(state.coins[node.Point()].sequence, 1U);
    BOOST_CHECK_EQUAL(state.coins[node.Point()].registrationHeight, 20);
    BOOST_CHECK(!CheckCNRegistrationTx(state, tx));
    ApplyCNPayeeTx(state, tx, 120);
    BOOST_CHECK_EQUAL(state.coins[node.Point()].registrationHeight, 20);
}

BOOST_AUTO_TEST_CASE(wrong_missing_and_reused_payments_are_refused)
{
    Heights heights;
    CTransaction reward;
    reward.vout.push_back(CTxOut(2 * COIN, Payee(1)));
    BOOST_CHECK(CheckCNPayeePayment(200, reward, Payee(1), 2 * COIN, {}));
    BOOST_CHECK(!CheckCNPayeePayment(200, reward, Payee(2), 2 * COIN, {}));
    BOOST_CHECK(!CheckCNPayeePayment(200, reward, Payee(1), COIN, {}));
    BOOST_CHECK(!CheckCNPayeePayment(200, reward, Payee(1), 2 * COIN, reward.vout));
    reward.vout.clear();
    BOOST_CHECK(!CheckCNPayeePayment(200, reward, Payee(1), 2 * COIN, {}));
    BOOST_CHECK(CheckCNPayeePayment(199, reward, Payee(1), 2 * COIN, {}));
}

BOOST_AUTO_TEST_CASE(no_cn_falls_back_to_producer_without_changing_split)
{
    Heights heights;
    CCNPayeeState state;
    CScript payee;
    BOOST_CHECK(!SelectCNPayee(state, 199, payee));
    CTransaction reward;
    reward.vout.push_back(CTxOut(COIN, Payee(5)));
    BOOST_CHECK(CheckCNPayeePayment(200, reward, payee, COIN, {}));
    const auto paid = CBlockSubsidySplit::ForBlock(200, COIN, 10, CollateralnodeShare::Paid);
    const auto fallback = CBlockSubsidySplit::ForBlock(200, COIN, 10, CollateralnodeShare::None);
    BOOST_CHECK_EQUAL(paid.Producer() + paid.Collateralnode(), fallback.Producer());
    BOOST_CHECK_EQUAL(paid.FinalityReserve(), fallback.FinalityReserve());
}

BOOST_AUTO_TEST_CASE(registration_state_and_undo_survive_reopening)
{
    LOCK(cs_main);
    Chain chain;
    CBlockIndex* parent = chain.Add(NULL);
    CBlockIndex* child = chain.Add(parent);
    Node node(7), other(8);
    CCNPayeeState state, saved;
    ApplyCNPayeeTx(state, node.collateral, 0);
    ApplyCNPayeeTx(state, node.Registration(), 0);
    state.hashTip = parent->GetBlockHash();
    saved = state;
    CCNPayeeUndo undo;
    node.nodeKey = other.nodeKey;
    ApplyCNPayeeTx(state, node.Registration(2), 1, &undo);
    CTransaction spend;
    spend.vin.push_back(CTxIn(node.Point()));
    ApplyCNPayeeTx(state, spend, 1, &undo);
    ApplyCNPayeeTx(state, other.collateral, 1, &undo);
    ApplyCNPayeeTx(state, other.Registration(), 1, &undo);
    state.hashTip = child->GetBlockHash();
    CTxDB db;
    CCNPayeeState old;
    const TxDBReadStatus oldStatus = db.ReadCNPayeeState(old);
    BOOST_REQUIRE(oldStatus != TXDB_READ_ERROR);
    BOOST_REQUIRE(db.TxnBegin());
    BOOST_REQUIRE(db.WriteCNPayeeState(state));
    BOOST_REQUIRE(db.WriteCNPayeeUndo(state.hashTip, undo));
    BOOST_REQUIRE(db.TxnCommit(true));
    db.Close();
    CTxDB reopened;
    CCNPayeeState persisted;
    BOOST_REQUIRE(reopened.ReadCNPayeeState(persisted) == TXDB_READ_FOUND);
    BOOST_CHECK(persisted.coins == state.coins);
    BOOST_REQUIRE(reopened.TxnBegin());
    BOOST_REQUIRE(UndoCNPayeeState(reopened, child));
    CCNPayeeState restored;
    BOOST_REQUIRE(reopened.ReadCNPayeeState(restored) == TXDB_READ_FOUND);
    BOOST_CHECK(restored.hashTip == saved.hashTip);
    BOOST_CHECK(restored.coins == saved.coins);
    BOOST_CHECK_EQUAL(restored.coins[node.Point()].sequence, 1U);
    BOOST_CHECK(!CheckCNRegistrationTx(restored, node.Registration()));
    BOOST_CHECK(CheckCNRegistrationTx(restored, node.Registration(2)));
    BOOST_REQUIRE(reopened.TxnAbort());
    BOOST_REQUIRE(reopened.EraseCNPayeeUndo(state.hashTip));
    if (oldStatus == TXDB_READ_FOUND) BOOST_REQUIRE(reopened.WriteCNPayeeState(old));
    else BOOST_REQUIRE(reopened.EraseCNPayeeState());
}

BOOST_AUTO_TEST_CASE(startup_registration_is_gated_by_activation)
{
    Heights heights;
    fRegTest = false;
    fTestNet = false;
    BOOST_CHECK(GetCNRegistrationPolicy(1) == CN_REGISTRATION_UNUSED);
    BOOST_CHECK(GetCNRegistrationPolicy(8790000 - CN_REGISTRATION_LEAD_BLOCKS - 1) == CN_REGISTRATION_UNUSED);
    BOOST_CHECK(GetCNRegistrationPolicy(8790000 - CN_REGISTRATION_LEAD_BLOCKS) == CN_REGISTRATION_OPTIONAL);
    BOOST_CHECK(GetCNRegistrationPolicy(8789999) == CN_REGISTRATION_OPTIONAL);
    BOOST_CHECK(GetCNRegistrationPolicy(8790000) == CN_REGISTRATION_REQUIRED);
    fTestNet = true;
    BOOST_CHECK(GetCNRegistrationPolicy(1) == CN_REGISTRATION_UNUSED);
    BOOST_CHECK(GetCNRegistrationPolicy(9000000) == CN_REGISTRATION_UNUSED);
    fRegTest = true;
    BOOST_CHECK(GetCNRegistrationPolicy(199) == CN_REGISTRATION_OPTIONAL);
    BOOST_CHECK(GetCNRegistrationPolicy(200) == CN_REGISTRATION_REQUIRED);
}

BOOST_AUTO_TEST_SUITE_END()

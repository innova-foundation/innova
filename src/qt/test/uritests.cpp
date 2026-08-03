#include "uritests.h"
#include "../uriutil.h"

#include <QUrl>

void URITests::uriTests()
{
    URIUtil::Recipient rv;
    QUrl uri;
    uri.setUrl(QString("innova:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-dontexist="));
    QVERIFY(!URIUtil::Parse(uri, &rv));

    uri.setUrl(QString("innova:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?dontexist="));
    QVERIFY(URIUtil::Parse(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("innova:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Wikipedia Example Address"));
    QVERIFY(URIUtil::Parse(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("innova:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=0.001"));
    QVERIFY(URIUtil::Parse(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(QString("innova:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1.001"));
    QVERIFY(URIUtil::Parse(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(QString("innova:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&label=Wikipedia Example"));
    QVERIFY(URIUtil::Parse(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString("innova:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address"));
    QVERIFY(URIUtil::Parse(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    QVERIFY(URIUtil::Parse("innova://175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address", &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    // We currently don't implement the message parameter (ok, yea, we break spec...)
    uri.setUrl(QString("innova:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-message=Wikipedia Example Address"));
    QVERIFY(!URIUtil::Parse(uri, &rv));

    uri.setUrl(QString("innova:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!URIUtil::Parse(uri, &rv));

    uri.setUrl(QString("innova:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000.0&label=Wikipedia Example"));
    QVERIFY(!URIUtil::Parse(uri, &rv));

    QVERIFY(!URIUtil::Parse(
        "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W", &rv));
}

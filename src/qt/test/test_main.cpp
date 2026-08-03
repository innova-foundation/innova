#include <QTest>
#include <QObject>
#include <QCoreApplication>

#include "policytests.h"
#include "uritests.h"

// This is all you need to run all the tests
int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    bool fInvalid = false;

    URITests test1;
    if (QTest::qExec(&test1, argc, argv) != 0)
        fInvalid = true;

    PolicyTests test2;
    if (QTest::qExec(&test2, argc, argv) != 0)
        fInvalid = true;

    return fInvalid;
}

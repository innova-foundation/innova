#ifndef INNOVA_QT_URIUTIL_H
#define INNOVA_QT_URIUTIL_H

#include <QString>

class QUrl;

namespace URIUtil
{

struct Recipient
{
    QString address;
    QString label;
    qint64 amount;

    Recipient() : amount(0) {}
};

/** Parse an innova: payment URI without requiring the wallet model. */
bool Parse(const QUrl& uri, Recipient* out);
bool Parse(QString uri, Recipient* out);

} // namespace URIUtil

#endif // INNOVA_QT_URIUTIL_H

#include "uriutil.h"

#include "bitcoinunits.h"

#include <QUrl>
#include <QUrlQuery>

namespace URIUtil
{

bool Parse(const QUrl& uri, Recipient* out)
{
    if (!uri.isValid() || uri.scheme() != QStringLiteral("innova"))
        return false;

    Recipient recipient;
    recipient.address = uri.path();

    const QUrlQuery query(uri);
    const QList<QPair<QString, QString> > items = query.queryItems();
    for (const QPair<QString, QString>& item : items)
    {
        QString key = item.first;
        bool required = false;
        if (key.startsWith(QStringLiteral("req-")))
        {
            key.remove(0, 4);
            required = true;
        }

        if (key == QStringLiteral("label"))
        {
            recipient.label = item.second;
            required = false;
        }
        else if (key == QStringLiteral("amount"))
        {
            if (!item.second.isEmpty() &&
                !BitcoinUnits::parse(BitcoinUnits::BTC, item.second,
                                     &recipient.amount))
                return false;
            required = false;
        }

        if (required)
            return false;
    }

    if (out)
        *out = recipient;
    return true;
}

bool Parse(QString uri, Recipient* out)
{
    // QUrl treats the value after // as a host and normalizes its case. Strip
    // the compatibility spelling before parsing so case-sensitive addresses
    // remain byte-for-byte unchanged.
    const QString compatibilityPrefix = QStringLiteral("innova://");
    if (uri.startsWith(compatibilityPrefix))
        uri.replace(0, compatibilityPrefix.size(), QStringLiteral("innova:"));
    return Parse(QUrl(uri), out);
}

} // namespace URIUtil

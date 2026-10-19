#ifndef LINKPREVIEW_H
#define LINKPREVIEW_H

#include <QObject>
#include <QByteArray>
#include <QNetworkProxy>
#include <QPointer>
#include <QString>
#include <QUrl>

class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

/** Sender-side link preview fetch. Runs only in the sending wallet, over the node proxy when one is
 *  set; recipients never contact the linked site. */
class LinkPreviewFetcher : public QObject
{
    Q_OBJECT

public:
    explicit LinkPreviewFetcher(QObject *parent = 0);
    ~LinkPreviewFetcher();

    /** Starts a fetch, cancelling any in flight. Returns false when policy refuses the URL. */
    bool start(const QString& url);
    void cancel();
    bool busy() const { return !pageUrl.isEmpty(); }
    QString currentUrl() const { return pageUrl; }

signals:
    /** thumb is a small JPEG or empty. ok=false means no card. */
    void finished(const QString& url, bool ok, const QString& title, const QString& desc,
                  const QString& site, const QByteArray& thumb);

private:
    QNetworkAccessManager *nam;
    QPointer<QNetworkReply> reply;
    QTimer *deadline;
    QString pageUrl;
    QString title, desc, site;
    QByteArray body;
    int redirects;
    bool fImage;
    bool fUseProxy;
    QNetworkProxy proxy;
    quint64 generation;

    void dropReply();
    void failStep();
    void send(const QUrl& u);

    bool choosePolicy(const QUrl& u);
    void request(const QUrl& u);
    void onMeta();
    void onData();
    void onDone();
    void finish(bool ok, const QByteArray& thumb = QByteArray());
    void finishPage();
    void finishImage();
};

#endif // LINKPREVIEW_H

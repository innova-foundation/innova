#include "linkpreview.h"

#include "nyxembed.h"
#include "netbase.h"
#include "net.h"

#include <QBuffer>
#include <QImage>
#include <QImageReader>
#include <QNetworkAccessManager>
#include <QNetworkCookieJar>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>

static const int PAGE_CAP = 512 * 1024;
static const int IMAGE_CAP = 2 * 1024 * 1024;
static const int MAX_REDIRECTS = 3;
static const int TOTAL_MS = 20000;
static const int IDLE_MS = 10000;
static const int THUMB_TARGET = 1536;

LinkPreviewFetcher::LinkPreviewFetcher(QObject *parent) :
    QObject(parent), nam(new QNetworkAccessManager(this)), deadline(new QTimer(this)),
    redirects(0), fImage(false), generation(0)
{
    nam->setCookieJar(new QNetworkCookieJar(nam));
    nam->setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
    deadline->setSingleShot(true);
    connect(deadline, &QTimer::timeout, this, [this]() { finish(false); });
}

LinkPreviewFetcher::~LinkPreviewFetcher()
{
    dropReply();
}

void LinkPreviewFetcher::dropReply()
{
    if (!reply)
        return;
    QNetworkReply *r = reply;
    reply = 0;
    r->disconnect(this);
    r->abort();
    r->deleteLater();
}

void LinkPreviewFetcher::cancel()
{
    deadline->stop();
    dropReply();
    generation++;
    pageUrl.clear();
}

// Tor only: no SOCKS proxy for onion traffic means no fetch, never a direct connection.
bool LinkPreviewFetcher::choosePolicy(const QUrl& u)
{
    if (u.scheme() != "https" || u.port(443) != 443)
        return false;
    const std::string host = u.host(QUrl::FullyEncoded).toLower().toStdString();
    proxyType pTor;
    if (!GetProxy(NET_TOR, pTor) || !pTor.first.IsValid() || !NyxIsFetchableHost(host, true))
        return false;
    proxy = QNetworkProxy(QNetworkProxy::Socks5Proxy,
                          QString::fromStdString(pTor.first.ToStringIP()), pTor.first.GetPort());
    proxy.setCapabilities(proxy.capabilities() | QNetworkProxy::HostNameLookupCapability);
    nam->setProxy(proxy);
    return true;
}

bool LinkPreviewFetcher::start(const QString& url)
{
    cancel();
    QUrl u(url, QUrl::StrictMode);
    if (!u.isValid() || !NyxIsLinkableUrl(url.toStdString()) || !choosePolicy(u))
        return false;
    pageUrl = url;
    title.clear(); desc.clear(); site.clear();
    redirects = 0;
    fImage = false;
    deadline->start(TOTAL_MS);
    request(u);
    return true;
}

void LinkPreviewFetcher::request(const QUrl& u)
{
    if (!choosePolicy(u))
    {
        failStep();
        return;
    }
    send(u);
}

void LinkPreviewFetcher::failStep()
{
    if (fImage) finish(true); else finish(false);
}

void LinkPreviewFetcher::send(const QUrl& u)
{
    QNetworkRequest req(u);
    req.setHeader(QNetworkRequest::UserAgentHeader, "Mozilla/5.0");
    req.setRawHeader("Accept", fImage ? "image/jpeg,image/png,image/webp,image/gif" : "text/html");
    req.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
    req.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    req.setTransferTimeout(IDLE_MS);
    body.clear();
    reply = nam->get(req);
    connect(reply, &QNetworkReply::metaDataChanged, this, &LinkPreviewFetcher::onMeta);
    connect(reply, &QNetworkReply::readyRead, this, &LinkPreviewFetcher::onData);
    connect(reply, &QNetworkReply::finished, this, &LinkPreviewFetcher::onDone);
}

void LinkPreviewFetcher::onMeta()
{
    if (!reply)
        return;
    int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (status >= 300 && status < 400)
        return;
    QString ct = reply->header(QNetworkRequest::ContentTypeHeader).toString().toLower();
    bool ok = fImage ? (ct.startsWith("image/jpeg") || ct.startsWith("image/png")
                        || ct.startsWith("image/webp") || ct.startsWith("image/gif"))
                     : ct.startsWith("text/html");
    qint64 len = reply->header(QNetworkRequest::ContentLengthHeader).toLongLong();
    if (!ok || (fImage && len > IMAGE_CAP))
    {
        dropReply();
        failStep();
    }
}

void LinkPreviewFetcher::onData()
{
    if (!reply || reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 200)
        return;
    body += reply->read((fImage ? IMAGE_CAP : PAGE_CAP) + 1 - body.size());
    bool fEnough = !fImage && body.contains("</head>");
    if (body.size() > (fImage ? IMAGE_CAP : PAGE_CAP) || fEnough)
    {
        if (body.size() > (fImage ? IMAGE_CAP : PAGE_CAP) && fImage)
            body.clear();
        dropReply();
        if (fImage) finishImage(); else finishPage();
    }
}

void LinkPreviewFetcher::onDone()
{
    if (!reply)
        return;
    QNetworkReply *r = reply;
    r->deleteLater();
    reply = 0;
    int status = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (status >= 300 && status < 400)
    {
        QUrl next = r->url().resolved(r->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl());
        if (++redirects > MAX_REDIRECTS || !NyxIsLinkableUrl(next.toString(QUrl::FullyEncoded).toStdString()))
        {
            failStep();
            return;
        }
        request(next);
        return;
    }
    if (r->error() != QNetworkReply::NoError || status != 200)
    {
        failStep();
        return;
    }
    if (fImage) finishImage(); else finishPage();
}

void LinkPreviewFetcher::finishPage()
{
    NyxPageMeta m = NyxParseHead(std::string(body.constData(), body.size()), pageUrl.toStdString());
    title = QString::fromStdString(m.title);
    desc = QString::fromStdString(m.desc);
    site = QString::fromStdString(m.site);
    if (title.isEmpty() && desc.isEmpty())
    {
        finish(false);
        return;
    }
    if (m.image.empty())
    {
        finish(true);
        return;
    }
    fImage = true;
    redirects = 0;
    request(QUrl(QString::fromStdString(m.image), QUrl::StrictMode));
}

void LinkPreviewFetcher::finishImage()
{
    QBuffer buf(&body);
    buf.open(QIODevice::ReadOnly);
    QImageReader rd(&buf);
    rd.setAllocationLimit(64);
    QSize sz = rd.size();
    if (!sz.isValid() || sz.width() > 8192 || sz.height() > 8192)
    {
        finish(true);
        return;
    }
    if (sz.width() > 800 || sz.height() > 800)
        rd.setScaledSize(sz.scaled(800, 800, Qt::KeepAspectRatio));
    QImage img = rd.read();
    if (img.isNull())
    {
        finish(true);
        return;
    }
    // Re-encoded here so no source bytes or metadata are forwarded.
    QImage sq = img.scaled(64, 64, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
    sq = sq.copy((sq.width() - 64) / 2, (sq.height() - 64) / 2, 64, 64).convertToFormat(QImage::Format_RGB888);
    static const int qualities[] = {60, 45, 32, 20};
    for (int q : qualities)
    {
        QByteArray jpg;
        QBuffer out(&jpg);
        out.open(QIODevice::WriteOnly);
        if (sq.save(&out, "JPEG", q) && jpg.size() <= THUMB_TARGET)
        {
            finish(true, jpg);
            return;
        }
    }
    finish(true);
}

void LinkPreviewFetcher::finish(bool ok, const QByteArray& thumb)
{
    if (pageUrl.isEmpty())
        return;
    QString url = pageUrl;
    cancel();
    emit finished(url, ok && (!title.isEmpty() || !desc.isEmpty()), title, desc, site, thumb);
}

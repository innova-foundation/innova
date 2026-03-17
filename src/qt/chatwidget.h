#ifndef CHATWIDGET_H
#define CHATWIDGET_H

#include <QWidget>
#include <QListWidget>
#include <QListView>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSortFilterProxyModel>
#include <QProgressBar>
#include <QTimer>
#include <QMap>
#include <QSet>
#include <QSettings>
#include <QtConcurrent/QtConcurrent>
#include <QFutureWatcher>

class MessageModel;
class WalletModel;
class EmojiPicker;
class EmojiAutocomplete;

/** Discord-like chat widget with contacts panel and conversation view */
class ChatWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ChatWidget(QWidget *parent = 0);
    ~ChatWidget();
    void setModel(MessageModel *msgModel, WalletModel *walletModel);

    /** Check if a message is an encrypted file attachment.
     *  Format: [file:CID:encKeyHex:filename:sizeBytes] */
    static bool isFileMessage(const QString& text);
    static bool parseFileMessage(const QString& text, QString& cid, QString& encKeyHex,
                                 QString& filename, qint64& size);

public slots:
    void onNewMessage();
    void onTypingReceived(const QString& senderAddr);

private slots:
    void onContactSelected(int row);
    void onSendClicked();
    void onNewChatClicked();
    void onFileAttachClicked();
    void onFileDownloadClicked(const QString& cid, const QString& encKeyHex, const QString& filename);
    void onFileUploadFinished();
    void onDeleteConversationClicked();
    void onRenameConversationClicked();
    void onTypingTimeout();
    void onSendTypingNotification();

private:
    MessageModel *msgModel;
    WalletModel *walletModel;

    // Left panel -- contacts
    QListWidget *contactList;
    QPushButton *newChatButton;
    QPushButton *deleteConversationButton;
    QPushButton *renameConversationButton;

    // Right panel -- conversation
    QLabel *chatHeader;
    QLabel *ipfsBanner;  // Red banner when IPFS gateway unreachable
    QListWidget *chatView;
    QTextEdit *messageInput;
    QPushButton *sendButton;
    QPushButton *emojiButton;
    QPushButton *attachButton;
    EmojiPicker *emojiPicker;
    EmojiAutocomplete *emojiAutocomplete;

    void refreshContacts();
    void loadConversation(const QString& address);
    void addChatBubble(const QString& text, const QString& time, bool isMine);
    void addFileBubble(const QString& cid, const QString& encKeyHex,
                       const QString& filename, qint64 size, const QString& time, bool isMine);

    /** Encrypt file with AES-256-GCM and upload to IPFS.
     *  For files > CHUNK_SIZE, uses chunked upload with manifest.
     *  Thread-safe: no QMessageBox calls. Returns true on success. Error in outError. */
    bool encryptAndUploadFile(const QString& filePath, QString& outCID, QString& outKeyHex, QString& outError);

    /** Download from IPFS and decrypt file with AES-256-GCM key.
     *  Supports both single-blob and chunked manifest formats.
     *  Returns true on success, fills outData. */
    bool downloadAndDecryptFile(const QString& cid, const QString& encKeyHex, QByteArray& outData);

    /** Check IPFS gateway connectivity. Returns max file size in bytes (0 = unavailable). */
    static qint64 checkIPFSGateway();

    /** Encrypt a single chunk with AES-256-GCM. Returns ciphertext with prepended tag. */
    static QByteArray encryptChunk(const QByteArray& plainData, const unsigned char* key,
                                   const unsigned char* baseNonce, uint32_t chunkIndex);

    /** Decrypt a single chunk. */
    static QByteArray decryptChunk(const QByteArray& cipherBlob, const unsigned char* key,
                                   const unsigned char* baseNonce, uint32_t chunkIndex);

    /** Get adaptive chunk size based on file size.
     *  1MB for < 50MB, 4MB for 50-500MB, 16MB for 500MB-2GB, 50MB for > 2GB. */
    static int getChunkSize(qint64 fileSize) {
        if (fileSize >= Q_INT64_C(2147483648)) return 50 * 1024 * 1024; // 50MB for 2GB+
        if (fileSize >= 500 * 1024 * 1024) return 16 * 1024 * 1024;    // 16MB for 500MB+
        if (fileSize >= 50 * 1024 * 1024) return 4 * 1024 * 1024;      // 4MB for 50MB+
        return 1024 * 1024; // 1MB default
    }
    /** Get number of parallel upload workers based on file size. */
    static int getParallelUploads(qint64 fileSize) {
        if (fileSize >= Q_INT64_C(2147483648)) return 8; // 8 concurrent for 2GB+
        if (fileSize >= 500 * 1024 * 1024) return 6;     // 6 concurrent for 500MB+
        if (fileSize >= 50 * 1024 * 1024) return 4;      // 4 concurrent for 50MB+
        return 1; // sequential for small files
    }
    static const int CHUNK_SIZE = 1024 * 1024; // default for small files

    QString currentContact;

    // Async file upload state
    QString pendingUploadFilePath;
    qint64 pendingUploadFileSize;
    QFutureWatcher<QPair<QString, QString>> *uploadWatcher;

    // Typing indicator state
    QMap<QString, qint64> mapTypingContacts; // address -> timestamp of last typing signal
    QTimer *typingDisplayTimer;    // fires every 1s to clear stale typing indicators
    QTimer *typingSendTimer;       // rate-limit outbound typing notifications (max 1 per 3s)
    bool typingSendPending;
    qint64 cachedIPFSMaxSize;      // cached gateway check result (0 = unchecked/unavailable)
    QMap<QString, qint64> mapLastReadTime; // address -> msec timestamp when conversation was last opened
    QMap<QString, QString> mapContactNicknames; // address -> user-assigned nickname

    void updateContactTypingDisplay();
};

#endif // CHATWIDGET_H

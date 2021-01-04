#ifndef JUPITER_H
#define JUPITER_H

#include <QWidget>
//#include <QWebView>

namespace Ui {
    class HyperFile;
}

/** HyperFile page widget */
class HyperFile : public QWidget
{
    Q_OBJECT

public:
    explicit HyperFile(QWidget *parent = 0);
    ~HyperFile();
    QString fileName;
    QString fileCont;

public slots:

signals:

private:
    Ui::HyperFile *ui;
    void noImageSelected();

private slots:
    void on_filePushButton_clicked();
    void on_createPushButton_clicked();
    void on_createPodButton_clicked();
    void on_checkButton_clicked();
    void on_checkButtonCloudflare_clicked();
    void on_checkHashButton_clicked();};

#endif // JUPITER_H

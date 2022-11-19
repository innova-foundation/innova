#ifndef HYPERFILE_H
#define HYPERFILE_H

#include <QWidget>
//#include <QWebView>

namespace Ui {
    class Hyperfile;
}

/** Hyperfile page widget */
class Hyperfile : public QWidget
{
    Q_OBJECT

public:
    explicit Hyperfile(QWidget *parent = 0);
    ~Hyperfile();
    QString fileName;
    QString fileCont;

public slots:

signals:

private:
    Ui::Hyperfile *ui;
    void noImageSelected();

private slots:
    void on_filePushButton_clicked();
    void on_createPushButton_clicked();
    void on_createPodButton_clicked();
    void on_checkButton_clicked();
    void on_checkButtonCloudflare_clicked();
    void on_checkHashButton_clicked();
};

#endif // HYPERFILE_H

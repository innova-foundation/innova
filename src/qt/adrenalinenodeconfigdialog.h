#ifndef ADRENALINENODECONFIGDIALOG_H
#define ADRENALINENODECONFIGDIALOG_H

#include <QDialog>

namespace Ui {
    class AdrenalineNodeConfigDialog;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Dialog showing transaction details. */
class AdrenalineNodeConfigDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AdrenalineNodeConfigDialog(QWidget *parent = 0, QString nodeAddress = "155.456.789.123:15539", QString privkey="COLLATERALNODEPRIVKEY");
    ~AdrenalineNodeConfigDialog();

private:
    Ui::AdrenalineNodeConfigDialog *ui;
};

#endif // ADRENALINENODECONFIGDIALOG_H

#ifndef MANAGENAMESPAGE_H
#define MANAGENAMESPAGE_H

#include <QDialog>
#include <QSortFilterProxyModel>
#include <QWidget>
#include <QTimer>

namespace Ui {
    class ManageNamesPage;
}
class WalletModel;
class NameTableModel;

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

class NameFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    explicit NameFilterProxyModel(QObject *parent = 0);

    void setNameSearch(const QString &search);
    void setValueSearch(const QString &search);
    void setAddressSearch(const QString &search);

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const;

private:
    QString nameSearch, valueSearch, addressSearch;
};

/** Page for managing names */
class ManageNamesPage : public QDialog
{
    Q_OBJECT

public:
    explicit ManageNamesPage(QWidget *parent = 0);
    ~ManageNamesPage();

    void setModel(WalletModel *walletModel);
    std::vector<unsigned char> importedAsBinaryFile;
    QString importedAsTextFile;

private:
    Ui::ManageNamesPage *ui;
    NameTableModel *model;
    WalletModel *walletModel;
    NameFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QTimer *timer;

public slots:
    void updateNames();
    void exportClicked();

    void changedNameFilter(const QString &filter);
    void changedValueFilter(const QString &filter);
    void changedAddressFilter(const QString &filter);

private slots:
    void on_submitNameButton_clicked();

    bool eventFilter(QObject *object, QEvent *event);
    void selectionChanged();

    /** Spawn contextual menu (right mouse menu) for name table entry */
    void contextualMenu(const QPoint &point);

    void onCopyNameAction();
    void onCopyValueAction();
    void onCopyAddressAction();
    void onCopyAllAction();
    void onSaveValueAsBinaryAction();
    void on_copyValueButton_clicked();
    void on_copyNameButton_clicked();

    void on_txTypeSelector_currentIndexChanged(const QString &txType);
    void on_cbMyNames_stateChanged(int arg1);
    void on_cbOtherNames_stateChanged(int arg1);
    void on_cbExpired_stateChanged(int arg1);
    void on_importValueButton_clicked();
    void on_registerValue_textChanged();
};

#endif // MANAGENAMESPAGE_H

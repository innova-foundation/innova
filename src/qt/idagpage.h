#ifndef IDAGPAGE_H
#define IDAGPAGE_H

#include <QString>
#include <QWidget>

class ClientModel;
class QGridLayout;
class QLabel;
class QTableWidget;
class QTimer;

class IDAGPage : public QWidget
{
    Q_OBJECT

public:
    explicit IDAGPage(QWidget *parent = 0);

    void setModel(ClientModel *model);

public slots:
    void refresh();

private:
    ClientModel *clientModel;
    QTimer *refreshTimer;

    QLabel *statusValue;
    QLabel *heightValue;
    QLabel *tipsValue;
    QLabel *entriesValue;
    QLabel *algorithmValue;
    QLabel *inferredKValue;
    QLabel *adaptiveLimitValue;
    QLabel *utilizationValue;
    QLabel *bestTipValue;
    QLabel *bestScoreValue;
    QLabel *finalityValue;
    QLabel *epochValue;

    QTableWidget *recentBlocksTable;

    QLabel* addMetric(QGridLayout *layout, int row, int column, const QString &title);
    QString shortHash(const QString &hash) const;
    QString formatBytes(unsigned int bytes) const;
    QString formatPercent(double value) const;
    void setValue(QLabel *label, const QString &value, const QString &toolTip = QString());
};

#endif // IDAGPAGE_H

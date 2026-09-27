#ifndef IV5HOLDSWIDGET_H
#define IV5HOLDSWIDGET_H

#include <QWidget>

QT_BEGIN_NAMESPACE
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
QT_END_NAMESPACE

/** Held IV5 notes: list (z_listiv5holds), place and release (z_holdiv5note).
 *  A held note is skipped by every spend and note vote. */
class Iv5HoldsWidget : public QWidget
{
    Q_OBJECT

public:
    explicit Iv5HoldsWidget(QWidget* parent = 0);

public slots:
    void refresh();

private slots:
    void onHold();
    void onRelease();
    void onSelectionChanged();

private:
    QLabel* m_summary;
    QTableWidget* m_table;
    QLineEdit* m_noteEdit;
    QPushButton* m_hold;
    QPushButton* m_release;
    QLabel* m_status;
};

#endif // IV5HOLDSWIDGET_H

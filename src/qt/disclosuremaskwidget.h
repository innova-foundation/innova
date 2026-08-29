#ifndef DISCLOSUREMASKWIDGET_H
#define DISCLOSUREMASKWIDGET_H

#include <QWidget>

class QComboBox;
class QLabel;

/** Picks the three-bit disclosure mask of a v2008 payload. A set bit hides that field,
 *  so mask 7 publishes nothing and is the default; the mask itself is public. */
class DisclosureMaskWidget : public QWidget
{
    Q_OBJECT

public:
    explicit DisclosureMaskWidget(QWidget *parent = 0);

    int mask() const;
    void setMask(int nMask);
    bool isDefaultMask() const;

    /** Text for the confirmation dialog of whatever operation carries the mask. */
    QString confirmationText() const;

signals:
    void maskChanged(int nMask);

private slots:
    void onSelectionChanged(int index);

private:
    void refreshExplanation();

    QComboBox *maskCombo;
    QLabel *detailLabel;
    QLabel *publicMaskLabel;
    QLabel *receiverWarningLabel;
    QLabel *rarityWarningLabel;
};

#endif // DISCLOSUREMASKWIDGET_H

// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
// modernstyle.h -- a modern flat Qt Style Sheet theme (dark + light) for the
// Innova wallet. Applied globally via BitcoinGUI::applyTheme(). Aims for a clean
// 2026 look: neutral surfaces, an Innova-blue accent, generous spacing, rounded
// corners, and subtle hover/focus states across the standard widget set.

#ifndef INNOVA_MODERNSTYLE_H
#define INNOVA_MODERNSTYLE_H

// ---- Dark theme -------------------------------------------------------------
static const char *MODERN_DARK_QSS = R"QSS(
* { font-family: "SF Pro Text", "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px; outline: 0; }
QWidget { background-color: #14171c; color: #e6e8ec; }
QMainWindow, QDialog, QStackedWidget, QScrollArea, QScrollArea > QWidget > QWidget {
    background-color: #14171c; }
QFrame { border: none; }
QLabel { background: transparent; color: #e6e8ec; }
QToolTip { background-color: #1e222a; color: #e6e8ec; border: 1px solid #2c313b;
    border-radius: 6px; padding: 6px 8px; }

/* Cards / group boxes */
QGroupBox { background-color: #1a1e25; border: 1px solid #262b34; border-radius: 12px;
    margin-top: 14px; padding: 14px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 4px; color: #9aa2af; }
/* Overview dashboard cards */
#OverviewPage { background-color: #101318; }
#OverviewPage QFrame#frame, #OverviewPage QFrame#frame_2 { background-color: #1b212b; border: 1px solid #2b323d; border-radius: 14px; padding: 10px; }

/* Buttons */
QPushButton { background-color: #1283C4; color: #ffffff; border: none; border-radius: 8px;
    padding: 8px 16px; font-weight: 600; min-height: 18px; }
QPushButton:hover { background-color: #1a93d8; }
QPushButton:pressed { background-color: #0e6ea6; }
QPushButton:disabled { background-color: #2a2f39; color: #6b727e; }
QPushButton:flat { background: transparent; color: #1283C4; }
QPushButton:flat:hover { background: rgba(18,131,196,0.12); }

/* Text inputs */
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox, QDateTimeEdit {
    background-color: #1a1e25; color: #e6e8ec; border: 1px solid #2c313b; border-radius: 8px;
    padding: 7px 10px; selection-background-color: #1283C4; selection-color: #ffffff; }
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus,
QComboBox:focus, QDateTimeEdit:focus { border: 1px solid #1283C4; }
QLineEdit:disabled, QComboBox:disabled { color: #6b727e; background-color: #171b21; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView { background-color: #1a1e25; border: 1px solid #2c313b;
    border-radius: 8px; selection-background-color: #1283C4; selection-color: #ffffff; outline: 0; }

/* Tables / lists */
QTableView, QTreeView, QListView { background-color: #14171c; alternate-background-color: #171b21;
    border: 1px solid #20242c; border-radius: 10px; gridline-color: #20242c;
    selection-background-color: rgba(18,131,196,0.22); selection-color: #ffffff; }
QTableView::item, QTreeView::item, QListView::item { padding: 6px 8px; border: none; }
QTableView::item:hover, QListView::item:hover { background-color: #1b2028; }
QHeaderView::section { background-color: #171b21; color: #9aa2af; border: none;
    border-bottom: 1px solid #262b34; padding: 8px 10px; font-weight: 600; }
QHeaderView::section:hover { color: #e6e8ec; }
QTableCornerButton::section { background-color: #171b21; border: none; }

/* Tabs */
QTabWidget::pane { border: 1px solid #262b34; border-radius: 10px; top: -1px; }
QTabBar::tab { background: transparent; color: #9aa2af; padding: 9px 16px; border: none;
    border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #ffffff; border-bottom: 2px solid #1283C4; }
QTabBar::tab:hover:!selected { color: #e6e8ec; }

/* Toolbar navigation -> modern sidebar/topbar */
QToolBar { background-color: #101318; border: none; padding: 6px; spacing: 4px; }
QToolBar::separator { background: #262b34; width: 1px; height: 1px; margin: 6px; }
QToolButton { background: transparent; color: #b6bcc7; border: none; border-radius: 8px;
    padding: 8px 12px; font-weight: 600; }
QToolButton:hover { background-color: #1b2028; color: #ffffff; }
QToolButton:checked { background-color: rgba(18,131,196,0.16); color: #4aa8e8; }
QToolButton:pressed { background-color: #1283C4; color: #ffffff; }
/* Left sidebar navigation */
QToolBar#navSidebar { background-color: #0f1216; border: none; border-right: 1px solid #20242c; padding: 12px 10px; spacing: 3px; }
QToolBar#navSidebar QToolButton { text-align: left; padding: 4px 12px; min-width: 148px; color: #aeb4bf; font-weight: 600; }
QToolBar#navSidebar QToolButton:hover { background-color: #1a1f27; color: #ffffff; }
QToolBar#navSidebar QToolButton:checked { background-color: rgba(18,131,196,0.16); color: #4aa8e8; }

/* Menus */
QMenuBar { background-color: #101318; color: #cfd4dc; }
QMenuBar::item { background: transparent; padding: 6px 12px; }
QMenuBar::item:selected { background-color: #1b2028; border-radius: 6px; }
QMenu { background-color: #1a1e25; color: #e6e8ec; border: 1px solid #2c313b; border-radius: 10px; padding: 6px; }
QMenu::item { padding: 7px 24px 7px 14px; border-radius: 6px; }
QMenu::item:selected { background-color: #1283C4; color: #ffffff; }
QMenu::separator { height: 1px; background: #262b34; margin: 6px 8px; }

/* Scrollbars */
QScrollBar:vertical { background: transparent; width: 12px; margin: 2px; }
QScrollBar::handle:vertical { background: #2c313b; border-radius: 5px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: #3a414d; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 2px; }
QScrollBar::handle:horizontal { background: #2c313b; border-radius: 5px; min-width: 28px; }
QScrollBar::handle:horizontal:hover { background: #3a414d; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; background: none; border: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

/* Progress / status */
QProgressBar { background-color: #1a1e25; border: none; border-radius: 6px; height: 8px; text-align: center; color: transparent; }
QProgressBar::chunk { background-color: #1283C4; border-radius: 6px; }
QStatusBar { background-color: #101318; color: #9aa2af; border-top: 1px solid #20242c; }
QStatusBar::item { border: none; }

/* Checks / radios */
QCheckBox, QRadioButton { spacing: 8px; background: transparent; }
QCheckBox::indicator, QRadioButton::indicator { width: 16px; height: 16px; border: 1px solid #3a414d; background: #1a1e25; }
QCheckBox::indicator { border-radius: 4px; }
QRadioButton::indicator { border-radius: 8px; }
QCheckBox::indicator:checked, QRadioButton::indicator:checked { background-color: #1283C4; border: 1px solid #1283C4; }
)QSS";

// ---- Light theme ------------------------------------------------------------
static const char *MODERN_LIGHT_QSS = R"QSS(
* { font-family: "SF Pro Text", "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px; outline: 0; }
QWidget { background-color: #f6f7f9; color: #1c2128; }
QMainWindow, QDialog, QStackedWidget, QScrollArea, QScrollArea > QWidget > QWidget { background-color: #f6f7f9; }
QFrame { border: none; }
QLabel { background: transparent; color: #1c2128; }
QToolTip { background-color: #ffffff; color: #1c2128; border: 1px solid #dfe3e8; border-radius: 6px; padding: 6px 8px; }
QGroupBox { background-color: #ffffff; border: 1px solid #e5e8ec; border-radius: 12px; margin-top: 14px; padding: 14px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 4px; color: #6b727e; }
#OverviewPage { background-color: #eef1f4; }
#OverviewPage QFrame#frame, #OverviewPage QFrame#frame_2 { background-color: #ffffff; border: 1px solid #e5e8ec; border-radius: 14px; padding: 10px; }
QPushButton { background-color: #1283C4; color: #ffffff; border: none; border-radius: 8px; padding: 8px 16px; font-weight: 600; min-height: 18px; }
QPushButton:hover { background-color: #1a93d8; }
QPushButton:pressed { background-color: #0e6ea6; }
QPushButton:disabled { background-color: #e5e8ec; color: #a3aab4; }
QPushButton:flat { background: transparent; color: #1283C4; }
QPushButton:flat:hover { background: rgba(18,131,196,0.10); }
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox, QDateTimeEdit {
    background-color: #ffffff; color: #1c2128; border: 1px solid #dfe3e8; border-radius: 8px; padding: 7px 10px;
    selection-background-color: #1283C4; selection-color: #ffffff; }
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus, QDateTimeEdit:focus { border: 1px solid #1283C4; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView { background-color: #ffffff; border: 1px solid #dfe3e8; border-radius: 8px; selection-background-color: #1283C4; selection-color: #ffffff; outline: 0; }
QTableView, QTreeView, QListView { background-color: #ffffff; alternate-background-color: #fafbfc; border: 1px solid #e5e8ec; border-radius: 10px; gridline-color: #eceff2;
    selection-background-color: rgba(18,131,196,0.14); selection-color: #1c2128; }
QTableView::item, QListView::item { padding: 6px 8px; }
QTableView::item:hover, QListView::item:hover { background-color: #f0f3f6; }
QHeaderView::section { background-color: #fafbfc; color: #6b727e; border: none; border-bottom: 1px solid #e5e8ec; padding: 8px 10px; font-weight: 600; }
QTabWidget::pane { border: 1px solid #e5e8ec; border-radius: 10px; top: -1px; }
QTabBar::tab { background: transparent; color: #6b727e; padding: 9px 16px; border: none; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #1c2128; border-bottom: 2px solid #1283C4; }
QToolBar { background-color: #ffffff; border: none; border-right: 1px solid #e5e8ec; padding: 6px; spacing: 4px; }
QToolButton { background: transparent; color: #4b5563; border: none; border-radius: 8px; padding: 8px 12px; font-weight: 600; }
QToolButton:hover { background-color: #f0f3f6; color: #1c2128; }
QToolButton:checked { background-color: rgba(18,131,196,0.12); color: #0e6ea6; }
QToolBar#navSidebar { background-color: #ffffff; border: none; border-right: 1px solid #e5e8ec; padding: 12px 10px; spacing: 3px; }
QToolBar#navSidebar QToolButton { text-align: left; padding: 4px 12px; min-width: 148px; color: #4b5563; font-weight: 600; }
QToolBar#navSidebar QToolButton:hover { background-color: #f0f3f6; color: #1c2128; }
QToolBar#navSidebar QToolButton:checked { background-color: rgba(18,131,196,0.12); color: #0e6ea6; }
QMenuBar { background-color: #ffffff; color: #1c2128; }
QMenuBar::item:selected { background-color: #f0f3f6; border-radius: 6px; }
QMenu { background-color: #ffffff; color: #1c2128; border: 1px solid #e5e8ec; border-radius: 10px; padding: 6px; }
QMenu::item { padding: 7px 24px 7px 14px; border-radius: 6px; }
QMenu::item:selected { background-color: #1283C4; color: #ffffff; }
QScrollBar:vertical { background: transparent; width: 12px; margin: 2px; }
QScrollBar::handle:vertical { background: #cdd3da; border-radius: 5px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: #b4bcc6; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QProgressBar { background-color: #e9edf1; border: none; border-radius: 6px; height: 8px; color: transparent; }
QProgressBar::chunk { background-color: #1283C4; border-radius: 6px; }
QStatusBar { background-color: #ffffff; color: #6b727e; border-top: 1px solid #e5e8ec; }
QCheckBox::indicator, QRadioButton::indicator { width: 16px; height: 16px; border: 1px solid #cdd3da; background: #ffffff; }
QCheckBox::indicator { border-radius: 4px; } QRadioButton::indicator { border-radius: 8px; }
QCheckBox::indicator:checked, QRadioButton::indicator:checked { background-color: #1283C4; border: 1px solid #1283C4; }
)QSS";

#endif // INNOVA_MODERNSTYLE_H

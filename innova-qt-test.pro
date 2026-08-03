TEMPLATE = app
TARGET = test_innova_qt

QT += core testlib
CONFIG += console testcase c++17 warn_on
CONFIG -= app_bundle

INCLUDEPATH += src src/qt
DEPENDPATH += src src/qt

QMAKE_CXXFLAGS += -Wall -Wextra -Werror

HEADERS += \
    src/qt/bitcoinunits.h \
    src/qt/privacyuipolicy.h \
    src/qt/stakinguipolicy.h \
    src/qt/uriutil.h \
    src/qt/test/policytests.h \
    src/qt/test/uritests.h

SOURCES += \
    src/qt/bitcoinunits.cpp \
    src/qt/privacyuipolicy.cpp \
    src/qt/stakinguipolicy.cpp \
    src/qt/uriutil.cpp \
    src/qt/test/policytests.cpp \
    src/qt/test/test_main.cpp \
    src/qt/test/uritests.cpp

qmake RELEASE=1 USE_UPNP=1 USE_QRCODE=1 USE_IPV6=1 innova-qt.pro
make
export QTDIR=/Users/circuitbreaker/Qt5.3.2/5.3/clang_64/
T=$(contrib/qt_translations.py $QTDIR/translations src/qt/locale)
python2.7 contrib/macdeploy/macdeployqtplus -add-qt-tr $T -dmg -fancy contrib/macdeploy/fancy.plist Innova.app

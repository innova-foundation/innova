#!/bin/bash

echo "Change line in innova-qt.pro"
sed -i 's/LIBS += -lcurl -lssl -lcrypto -lcrypt32 -lssh2 -lgcrypt -lidn2 -lgpg-error -lunistring -lwldap32 -ldb_cxx$$BDB_LIB_SUFFIX/LIBS += -lcurl -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX/' innova-qt.pro

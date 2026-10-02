Translations
============

The Qt GUI can be translated into other languages. This section describes how
translations are handled.

Files and Folders
-----------------

### innova-qt.pro

This file takes care of generating `.qm` files from `.ts` files. It is mostly
automated.

### src/qt/bitcoin.qrc

This file must be updated whenever a new translation is added. Files must end
with `.qm`, not `.ts`.

    <qresource prefix="/translations">
        <file alias="en">locale/bitcoin_en.qm</file>
        ...
    </qresource>

### src/qt/locale/

This directory contains all translations. Filenames must adhere to this format:

    bitcoin_xx_YY.ts or bitcoin_xx.ts

#### Source file

`src/qt/locale/bitcoin_en.ts` is treated in a special way. It is used as the
source for all other translations. Whenever a string in the code is changed
this file must be updated to reflect those changes. Usually, this can be
accomplished by running `lupdate` (included in the Qt SDK).

Translations are edited in the `.ts` files with Qt Linguist and submitted as
pull requests.

### Adding or updating a translation

1. Run `lupdate` to refresh `src/qt/locale/bitcoin_en.ts` from the source.
2. Copy it to `src/qt/locale/bitcoin_xx.ts` (new language) or open the existing
   file, and translate it in Qt Linguist.
3. Add a new language to `src/qt/bitcoin.qrc`, for example with
   `ls src/qt/locale/*ts|xargs -n1 basename|sed 's/\(bitcoin_\(.*\)\).ts/<file alias="\2">locale/\1.qm<\/file>/'`
4. `git add` the `.ts` file and the `.qrc` change, and open a pull request.

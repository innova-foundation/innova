Unicode true
!ifndef VERSION
  !define VERSION 0.0.0.0
!endif
!ifndef PKGDIR
  !define PKGDIR ..\release
!endif
!ifndef OUTFILE
  !define OUTFILE innova-${VERSION}-win64-setup.exe
!endif

!define APP Innova
!define COMPANY "Innova Foundation"
!define URL https://innova-foundation.com
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Innova"

Name "${APP} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\${APP}"
InstallDirRegKey HKLM "Software\${APP}" Path
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show
BrandingText "${APP} ${VERSION}"

VIProductVersion ${VERSION}
VIAddVersionKey ProductName "${APP}"
VIAddVersionKey ProductVersion "${VERSION}"
VIAddVersionKey CompanyName "${COMPANY}"
VIAddVersionKey FileVersion "${VERSION}"
VIAddVersionKey FileDescription "${APP} wallet installer"
VIAddVersionKey LegalCopyright "MIT License"

!define MUI_ICON "pixmaps\innova.ico"
!define MUI_UNICON "pixmaps\innova.ico"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Start ${APP}"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchUnelevated

!include MUI2.nsh
!include x64.nsh

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\COPYING"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE English

!macro RequireClosed EXE
  nsExec::ExecToStack 'cmd /c tasklist /FI "IMAGENAME eq ${EXE}" /NH | find /I "${EXE}"'
  Pop $0
  ${If} $0 == 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "${EXE} is running. Close it and run setup again."
    Abort
  ${EndIf}
!macroend

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "${APP} requires 64-bit Windows."
    Abort
  ${EndIf}
  SetRegView 64
  !insertmacro RequireClosed Innova.exe
  !insertmacro RequireClosed innovad.exe
FunctionEnd

# The installer runs elevated; start the wallet as the signed-in user.
Function LaunchUnelevated
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\Innova.exe"'
FunctionEnd

Section "Innova" SecMain
  SectionIn RO
  SetOutPath "$INSTDIR"
  SetOverwrite on
  File "${PKGDIR}\Innova.exe"
  File "${PKGDIR}\innovad.exe"
  File "${PKGDIR}\innova-cli.exe"
  File /oname=COPYING.txt "..\COPYING"

  nsExec::Exec 'netsh advfirewall firewall delete rule name="Innova"'
  nsExec::Exec 'netsh advfirewall firewall add rule name="Innova" dir=in action=allow program="$INSTDIR\Innova.exe" enable=yes profile=any'
  nsExec::Exec 'netsh advfirewall firewall add rule name="Innova" dir=in action=allow program="$INSTDIR\innovad.exe" enable=yes profile=any'

  SetShellVarContext all
  CreateDirectory "$SMPROGRAMS\${APP}"
  CreateShortcut "$SMPROGRAMS\${APP}\${APP}.lnk" "$INSTDIR\Innova.exe"
  CreateShortcut "$SMPROGRAMS\${APP}\Uninstall ${APP}.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$DESKTOP\${APP}.lnk" "$INSTDIR\Innova.exe"

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\${APP}" Path "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" DisplayName "${APP}"
  WriteRegStr HKLM "${UNINSTKEY}" DisplayVersion "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" Publisher "${COMPANY}"
  WriteRegStr HKLM "${UNINSTKEY}" URLInfoAbout "${URL}"
  WriteRegStr HKLM "${UNINSTKEY}" DisplayIcon "$INSTDIR\Innova.exe"
  WriteRegStr HKLM "${UNINSTKEY}" UninstallString '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTKEY}" InstallLocation "$INSTDIR"
  WriteRegDWORD HKLM "${UNINSTKEY}" NoModify 1
  WriteRegDWORD HKLM "${UNINSTKEY}" NoRepair 1
SectionEnd

Function un.onInit
  SetRegView 64
  !insertmacro RequireClosed Innova.exe
  !insertmacro RequireClosed innovad.exe
FunctionEnd

# Wallets and chain data in %APPDATA%\Innova are never touched.
Section "Uninstall"
  nsExec::Exec 'netsh advfirewall firewall delete rule name="Innova"'
  Delete "$INSTDIR\Innova.exe"
  Delete "$INSTDIR\innovad.exe"
  Delete "$INSTDIR\innova-cli.exe"
  Delete "$INSTDIR\COPYING.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  SetShellVarContext all
  Delete "$SMPROGRAMS\${APP}\${APP}.lnk"
  Delete "$SMPROGRAMS\${APP}\Uninstall ${APP}.lnk"
  RMDir "$SMPROGRAMS\${APP}"
  Delete "$DESKTOP\${APP}.lnk"
  DeleteRegKey HKLM "${UNINSTKEY}"
  DeleteRegKey HKLM "Software\${APP}"
SectionEnd

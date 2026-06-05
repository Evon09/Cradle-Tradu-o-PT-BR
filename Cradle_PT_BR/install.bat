@echo off
setlocal enabledelayedexpansion

REM pasta base (onde o bat esta)
set BASE=%~dp0

REM pasta do jogo data
set GAME_DIR=%BASE%..\data

REM pasta final da tradução
set LOCALE_DIR=%BASE%..\data\source\locale

REM pasta de extracção temporária
set TEMP=%BASE%extracted

REM pasta dos arquivos traduzidos
set TRANSLATION=%BASE%files

echo ==================================
echo Iniciando instalacao da traducao
echo ==================================

echo Criando pasta temporaria...
mkdir "%TEMP%" 2>nul

echo Extraindo arquivos .ung...

for %%F in ("%GAME_DIR%\*.ung") do (
    echo Extraindo %%~nxF
    "%BASE%uniginex.exe" "%%F" "%TEMP%"
)

echo Removendo arquivos .ung originais...
del /q "%GAME_DIR%\*.ung"

echo Copiando arquivos extraidos para o jogo...
xcopy "%TEMP%\*" "%GAME_DIR%\" /E /Y /I /R

echo Aplicando traducao (locale)...

xcopy "%TRANSLATION%\*" "%LOCALE_DIR%\" /Y /I /R

echo Limpando pasta temporaria...
rmdir /s /q "%TEMP%"

echo ==================================
echo Tradução instalada com sucesso!
echo ==================================
pause
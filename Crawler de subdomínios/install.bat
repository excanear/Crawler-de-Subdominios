@echo off
echo ========================================
echo    Subdomain Crawler - Instalacao
echo ========================================
echo.

:: Verificar se Go esta instalado
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERRO] Go nao encontrado!
    echo.
    echo Por favor, instale o Go primeiro:
    echo https://golang.org/dl/
    echo.
    pause
    exit /b 1
)

echo [INFO] Go encontrado:
go version

echo.
echo [INFO] Baixando dependencias...
go mod tidy

if %errorlevel% neq 0 (
    echo [ERRO] Falha ao baixar dependencias
    pause
    exit /b 1
)

echo.
echo [INFO] Compilando subdomain-crawler...
go build -ldflags="-s -w" -o subdomain-crawler.exe main.go

if %errorlevel% neq 0 (
    echo [ERRO] Falha na compilacao
    pause
    exit /b 1
)

echo.
echo [SUCESSO] Instalacao concluida!
echo.
echo Executavel criado: subdomain-crawler.exe
echo.
echo Exemplos de uso:
echo   subdomain-crawler.exe -d example.com
echo   subdomain-crawler.exe -d example.com --passive-only
echo   subdomain-crawler.exe -d example.com -w 50 -r 100
echo.
echo Para ver todas as opcoes:
echo   subdomain-crawler.exe --help
echo.
pause
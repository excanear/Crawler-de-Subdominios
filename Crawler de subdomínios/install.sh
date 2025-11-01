#!/bin/bash

echo "========================================"
echo "    Subdomain Crawler - Instalação"
echo "========================================"
echo

# Verificar se Go está instalado
if ! command -v go &> /dev/null; then
    echo "[ERRO] Go não encontrado!"
    echo
    echo "Por favor, instale o Go primeiro:"
    echo "https://golang.org/dl/"
    echo
    echo "No Ubuntu/Debian: sudo apt install golang-go"
    echo "No macOS: brew install go"
    echo
    exit 1
fi

echo "[INFO] Go encontrado:"
go version

echo
echo "[INFO] Baixando dependências..."
go mod tidy

if [ $? -ne 0 ]; then
    echo "[ERRO] Falha ao baixar dependências"
    exit 1
fi

echo
echo "[INFO] Compilando subdomain-crawler..."
go build -ldflags="-s -w" -o subdomain-crawler main.go

if [ $? -ne 0 ]; then
    echo "[ERRO] Falha na compilação"
    exit 1
fi

echo
echo "[SUCESSO] Instalação concluída!"
echo
echo "Executável criado: ./subdomain-crawler"
echo
echo "Exemplos de uso:"
echo "  ./subdomain-crawler -d example.com"
echo "  ./subdomain-crawler -d example.com --passive-only"
echo "  ./subdomain-crawler -d example.com -w 50 -r 100"
echo
echo "Para ver todas as opções:"
echo "  ./subdomain-crawler --help"
echo

# Tornar executável
chmod +x subdomain-crawler

echo "Pronto para uso!"
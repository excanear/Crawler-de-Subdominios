package main

import (
	"fmt"
	"os"

	"subdomain-crawler/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Printf("Erro: %v\n", err)
		os.Exit(1)
	}
}
/*
Copyright © 2026 HNCLR by Poyraz Boreas Hancilar
Licensed under the Apache License, Version 2.0
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

type PublicResult struct {
	FilePath     string `json:"file_path"`
	PublicKey    string `json:"public_key,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

var publicCmd = &cobra.Command{
	Use:   "public [file/dir]",
	Short: "Extract public key from private key",
	Long:  `Public command reads a private key and outputs its corresponding public key in OpenSSH format.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(colorize("Error: Please specify file or directory.", colorRed))
			return
		}
		HandlePath(args[0], PerformPublic)
	},
}

func PerformPublic(filePath string) {
	result := PublicResult{
		FilePath: filePath,
	}

	keyData, err := os.ReadFile(filePath)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error reading file: %v", err)
		printPublicResult(result)
		return
	}

	// Signer is the easiest way to get the public key from a private one in Go
	signer, err := ssh.ParseRawPrivateKey(keyData)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error parsing private key: %v", err)
		printPublicResult(result)
		return
	}

	sshSigner, err := ssh.NewSignerFromKey(signer)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error creating signer: %v", err)
		printPublicResult(result)
		return
	}

	pubKey := sshSigner.PublicKey()
	result.PublicKey = string(ssh.MarshalAuthorizedKey(pubKey))

	printPublicResult(result)
}

func printPublicResult(result PublicResult) {
	if jsonOutput || outputPath != "" {
		jsonResults = append(jsonResults, result)
	}

	if jsonOutput {
		return
	}

	if result.ErrorMessage != "" {
		fmt.Printf("%s File: %s | Error: %s\n", colorize("[ERROR]", colorRed), result.FilePath, result.ErrorMessage)
		return
	}

	if isBulkMode {
		fmt.Printf("File: %s\n%s", result.FilePath, result.PublicKey)
	} else {
		fmt.Print(result.PublicKey)
	}
}

func init() {
	rootCmd.AddCommand(publicCmd)
}

/*
Copyright © 2026 HNCLR by Poyraz Boreas Hancilar
Licensed under the Apache License, Version 2.0
*/
package cmd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

type InspectResult struct {
	FilePath       string `json:"file_path"`
	PEMType        string `json:"pem_type,omitempty"`
	KeyType        string `json:"key_type"`
	BitLength      int    `json:"bit_length,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	IsEncrypted    bool   `json:"is_encrypted"`
	Format         string `json:"format"`
	ForensicOrigin string `json:"forensic_origin,omitempty"`
	ErrorMessage   string `json:"error_message,omitempty"`
}

// inspectCmd represents the inspect command
var inspectCmd = &cobra.Command{
	Use:   "inspect [file/dir]",
	Short: "Inspect a key file and display its properties",
	Long:  `Inspect parses the given key file and displays technical details like type, bit length, and fingerprint.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Error: Please specify file or directory.")
			fmt.Println("E.g. Usage: keyxray inspect [path]")
			return
		}
		HandlePath(args[0], PerformInspect)
	},
}

func PerformInspect(filePath string) {
	result := InspectResult{
		FilePath: filePath,
	}

	keyData, err := os.ReadFile(filePath)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error reading file: %v", err)
		printInspectResult(result)
		return
	}

	// 1. PEM Decode
	block, _ := pem.Decode(keyData)
	if block == nil {
		result.ErrorMessage = "Warning: File is not in PEM format. It might be raw data (binary) or corrupted text."
		printInspectResult(result)
		return
	}
	result.PEMType = block.Type

	// Passphrase detection via PEM headers
	if x509.IsEncryptedPEMBlock(block) || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		result.IsEncrypted = true
	}

	// 2. SSH Parser
	privateKey, err := ssh.ParseRawPrivateKey(keyData)
	if err == nil {
		result.Format = "SSH"
		analyzeSSHKey(privateKey, &result)
		result.ForensicOrigin = guessOrigin(&result)
		printInspectResult(result)
		return
	}

	// Passphrase detection via error message
	if err != nil && (strings.Contains(err.Error(), "passphrase") || strings.Contains(err.Error(), "encrypted")) {
		result.IsEncrypted = true
		result.Format = "SSH (Encrypted)"
		result.KeyType = "Unknown (Encrypted)"
		result.ForensicOrigin = "Likely Modern OpenSSH (Encrypted)"
		printInspectResult(result)
		return
	}

	// 3. X509 / TLS Parser
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		result.Format = "X.509 (PKCS#8)"
		analyzeGenericKey(key, &result)
		result.ForensicOrigin = "Likely OpenSSL / TLS Generator"
		printInspectResult(result)
		return
	} else if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		result.Format = "X.509 (PKCS#1)"
		analyzeGenericKey(key, &result)
		result.ForensicOrigin = "Legacy OpenSSL or Old OpenSSH (< 7.8)"
		printInspectResult(result)
		return
	} else if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		result.Format = "X.509 (EC)"
		analyzeGenericKey(key, &result)
		result.ForensicOrigin = "Likely Modern Web Server Certificate"
		printInspectResult(result)
		return
	}

	result.ErrorMessage = "Unknown or unsupported key format."
	printInspectResult(result)
}

func guessOrigin(res *InspectResult) string {
	if res.PEMType == "OPENSSH PRIVATE KEY" {
		if res.KeyType == "ssh-ed25519" {
			return "Modern OpenSSH (Post-2014, likely macOS or Modern Linux)"
		}
		return "Modern OpenSSH (Post-2018 default format)"
	}
	
	if res.PEMType == "RSA PRIVATE KEY" {
		return "Legacy OpenSSL or Old OpenSSH (< 7.8)"
	}

	if res.Format == "X.509 (PKCS#8)" {
		return "Java/OpenSSL or Web Server Certificate"
	}

	return "Unknown Generation Tool"
}

func printInspectResult(result InspectResult) {
	if jsonOutput || outputPath != "" {
		jsonResults = append(jsonResults, result)
	}

	if jsonOutput {
		return
	}

	fmt.Println(colorize("------[INSPECTION] KEY DETAILS------", colorCyanBold))
	fmt.Printf("File		: %s\n", result.FilePath)
	if result.ErrorMessage != "" {
		fmt.Printf("Error		: %s\n", colorize(result.ErrorMessage, colorRed))
		return
	}
	fmt.Printf("PEM Type	: %s\n", result.PEMType)
	fmt.Printf("Format		: %s\n", result.Format)
	fmt.Printf("Key Type	: %s\n", colorize(result.KeyType, colorBold))
	if result.BitLength > 0 {
		fmt.Printf("Bit Length	: %s\n", colorize(fmt.Sprintf("%d", result.BitLength), colorBold))
	}
	if result.Fingerprint != "" {
		fmt.Printf("Fingerprint	: %s\n", colorize(result.Fingerprint, colorBold))
	}
	fmt.Printf("Encrypted	: %v\n", result.IsEncrypted)
	
	if result.ForensicOrigin != "" {
		fmt.Printf("Forensic Origin	: %s\n", colorize(result.ForensicOrigin, colorYellow))
	}
}

func analyzeSSHKey(key interface{}, result *InspectResult) {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error creating signer: %v", err)
		return
	}

	pubKey := signer.PublicKey()
	result.KeyType = pubKey.Type()
	result.Fingerprint = ssh.FingerprintSHA256(pubKey)

	switch k := key.(type) {
	case *rsa.PrivateKey:
		result.BitLength = k.N.BitLen()
	case *ecdsa.PrivateKey:
		result.BitLength = k.Curve.Params().BitSize
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		result.BitLength = 256
	}
}

func analyzeGenericKey(key interface{}, result *InspectResult) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		result.KeyType = "RSA"
		result.BitLength = k.N.BitLen()
	case *ecdsa.PrivateKey:
		result.KeyType = "ECDSA"
		result.BitLength = k.Curve.Params().BitSize
	case ed25519.PrivateKey:
		result.KeyType = "Ed25519"
		result.BitLength = 256
	default:
		result.KeyType = "Unknown"
	}
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}

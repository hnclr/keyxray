/*
Copyright © 2026 HNCLR by Poyraz Boreas Hancilar
Licensed under the Apache License, Version 2.0
*/
package cmd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

type AuditResult struct {
	FilePath      string `json:"file_path"`
	Permissions   string `json:"permissions"`
	IsPermSecure  bool   `json:"is_perm_secure"`
	Strength      string `json:"strength"`
	IsStrong      bool   `json:"is_strong"`
	Recommendations []string `json:"recommendations,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
}

// auditCmd represents the audit command
var auditCmd = &cobra.Command{
	Use:   "audit [file/dir]",
	Short: "Check for weak algorithms or risky permissions",
	Long:  `Audit checks file permissions and key strength to identify potential security risks.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Error: Please specify file or directory.")
			fmt.Println("E.g. Usage: keyxray audit [path]")
			return
		}
		HandlePath(args[0], PerformAudit)
	},
}

func PerformAudit(filePath string) {
	result := AuditResult{
		FilePath: filePath,
	}

	// 1. File Permissions
	info, err := os.Stat(filePath)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error accessing file: %v", err)
		printAuditResult(result)
		return
	}

	mode := info.Mode().Perm()
	result.Permissions = fmt.Sprintf("%04o", mode)
	if mode == 0600 {
		result.IsPermSecure = true
	} else {
		result.IsPermSecure = false
		result.Recommendations = append(result.Recommendations, "Change file permissions to 0600")
	}

	// 2. Key Power
	keyData, _ := os.ReadFile(filePath)
	key, err := ssh.ParseRawPrivateKey(keyData)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error parsing private key: %v", err)
		printAuditResult(result)
		return
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		bitLen := k.N.BitLen()
		result.Strength = fmt.Sprintf("%d-bit RSA", bitLen)
		if bitLen < 2048 {
			result.IsStrong = false
			result.Recommendations = append(result.Recommendations, "Upgrade to at least 2048-bit RSA or ED25519")
		} else {
			result.IsStrong = true
		}
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		result.Strength = "ED25519"
		result.IsStrong = true
	case *ecdsa.PrivateKey:
		bitSize := k.Curve.Params().BitSize
		result.Strength = fmt.Sprintf("ECDSA %d-bit", bitSize)
		result.IsStrong = true
	default:
		result.Strength = "Unknown"
		result.IsStrong = false
	}

	printAuditResult(result)
}

func printAuditResult(result AuditResult) {
	if jsonOutput || outputPath != "" {
		jsonResults = append(jsonResults, result)
	}

	if jsonOutput {
		return
	}

	fmt.Println(colorize("\n------[AUDIT] SECURITY ANALYSIS------", colorCyanBold))
	fmt.Printf("File		: %s\n", result.FilePath)
	if result.ErrorMessage != "" {
		fmt.Printf("%s Error	: %s\n", colorize("[ERROR]", colorRed), colorize(result.ErrorMessage, colorRed))
		return
	}

	if result.IsPermSecure {
		fmt.Printf("%s Permissions	: %s %s\n", colorize("[OK]", colorGreen), colorize(result.Permissions, colorBold), colorize("(Secure)", colorGreen))
	} else {
		fmt.Printf("%s Permissions	: %s %s\n", colorize("[WARNING]", colorYellow), colorize(result.Permissions, colorBold), colorize("(Insecure | Recommended: 0600)", colorYellow))
	}

	if result.IsStrong {
		fmt.Printf("%s Strength	: %s %s\n", colorize("[OK]", colorGreen), colorize(result.Strength, colorBold), colorize("(Secure)", colorGreen))
	} else {
		fmt.Printf("%s Strength	: %s %s\n", colorize("[CRITICAL]", colorRed), colorize(result.Strength, colorBold), colorize("(Too weak!)", colorRed))
	}

	if len(result.Recommendations) > 0 {
		fmt.Println(colorize("\nRecommendations:", colorYellow))
		for _, rec := range result.Recommendations {
			fmt.Printf("- %s\n", rec)
		}
	}
}

func init() {
	rootCmd.AddCommand(auditCmd)
}

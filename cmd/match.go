/*
Copyright © 2026 HNCLR by Poyraz Boreas Hancilar
Licensed under the Apache License, Version 2.0
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var matchCmd = &cobra.Command{
	Use:   "match [directory]",
	Short: "Find matching private and public keys",
	Long:  `Match scans a directory, calculates fingerprints, and pairs private keys with their corresponding public keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		dir := "."
		if len(args) > 0 {
			dir = args[0]
		}
		PerformMatch(dir)
	},
}

func PerformMatch(root string) {
	fmt.Printf("%s Scanning %s for key pairs...\n\n", colorize("[MATCHING]", colorCyanBold), root)

	// Fingerprint -> File paths
	privateKeys := make(map[string][]string)
	publicKeys := make(map[string][]string)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.Contains(path, "/.") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Try parsing as private key
		if signer, err := ssh.ParseRawPrivateKey(data); err == nil {
			if sshSigner, err := ssh.NewSignerFromKey(signer); err == nil {
				fp := ssh.FingerprintSHA256(sshSigner.PublicKey())
				privateKeys[fp] = append(privateKeys[fp], path)
				return nil
			}
		}

		// Try parsing as public key
		if pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data); err == nil {
			fp := ssh.FingerprintSHA256(pubKey)
			publicKeys[fp] = append(publicKeys[fp], path)
		}

		return nil
	})

	if err != nil {
		fmt.Printf("%s Error scanning directory: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	matchesFound := 0
	matchedFingerprints := make(map[string]bool)

	for fp, privPaths := range privateKeys {
		if pubPaths, ok := publicKeys[fp]; ok {
			matchesFound++
			matchedFingerprints[fp] = true
			fmt.Printf("%s Fingerprint: %s\n", colorize("=== PAIR FOUND ===", colorGreen), fp)
			for _, p := range privPaths {
				fmt.Printf("  Private : %s\n", colorize(p, colorBold))
			}
			for _, p := range pubPaths {
				fmt.Printf("  Public  : %s\n", p)
			}
			fmt.Println()
		}
	}

	// Report Orphaned Keys
	orphansFound := 0
	firstOrphan := true

	// Unmatched Private Keys
	for fp, privPaths := range privateKeys {
		if !matchedFingerprints[fp] {
			if firstOrphan {
				fmt.Printf("%s\n", colorize("=== ORPHANED KEYS (NO MATCH) ===", colorYellow))
				firstOrphan = false
			}
			orphansFound++
			for _, p := range privPaths {
				fmt.Printf("  [Private] : %s (%s)\n", colorize(p, colorBold), fp[:15]+"...")
			}
		}
	}

	// Unmatched Public Keys
	for fp, pubPaths := range publicKeys {
		if !matchedFingerprints[fp] {
			if firstOrphan {
				fmt.Printf("%s\n", colorize("=== ORPHANED KEYS (NO MATCH) ===", colorYellow))
				firstOrphan = false
			}
			orphansFound++
			for _, p := range pubPaths {
				fmt.Printf("  [Public]  : %s (%s)\n", p, fp[:15]+"...")
			}
		}
	}

	if matchesFound == 0 && orphansFound == 0 {
		fmt.Printf("%s No keys found in the directory.\n", colorize("[NOTICE]", colorYellow))
	} else {
		fmt.Printf("\n%s\n", colorize("--- SUMMARY ---", colorCyanBold))
		fmt.Printf("Pairs Found    : %d\n", matchesFound)
		fmt.Printf("Orphans Found  : %d\n", orphansFound)
	}
}

func init() {
	rootCmd.AddCommand(matchCmd)
}

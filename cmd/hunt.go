/*
Copyright © 2026 HNCLR by Poyraz Boreas Hancilar
Licensed under the Apache License, Version 2.0
*/
package cmd

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

type HuntResult struct {
	FilePath    string  `json:"file_path"`
	Offset      int64   `json:"offset,omitempty"`
	Reason      string  `json:"reason"`
	Entropy     float64 `json:"entropy,omitempty"`
	ExtractedTo string  `json:"extracted_to,omitempty"`
}

var deepHunt bool
var stegoScan bool
var extractBlobs bool

// huntCmd represents the hunt command
var huntCmd = &cobra.Command{
	Use:   "hunt [directory]",
	Short: "Hunt for private keys or hidden blobs in a directory",
	Long:  `Hunt recursively scans the specified directory for files that appear to be private keys. Standard mode checks the first 512 bytes, --deep mode scans the entire file content for PEM markers, and --stego mode uses entropy analysis to find hidden cryptographic blobs. Use --extract to save findings to disk.`,
	Run: func(cmd *cobra.Command, args []string) {
		dir := "."
		if len(args) > 0 {
			dir = args[0]
		}
		PerformHunt(dir)
	},
}

func PerformHunt(root string) {
	if !jsonOutput {
		mode := "Standard"
		if stegoScan {
			mode = "Steganography (Entropy Analysis)"
		} else if deepHunt {
			mode = "Deep (Aggressive)"
		}
		fmt.Println(colorize(fmt.Sprintf("[HUNTING] %s keys in: %s", mode, root), colorCyanBold))
		if extractBlobs {
			fmt.Println(colorize("[MODE] Extraction Enabled: Findings will be saved to disk.", colorYellow))
		}
	}

	count := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		found, offset, reason, entropy, rawData := detectKey(path)
		if found {
			count++
			res := HuntResult{FilePath: path, Offset: offset, Reason: reason, Entropy: entropy}
			
			if extractBlobs && len(rawData) > 0 {
				extPath := fmt.Sprintf("%s.extracted_%d.bin", filepath.Base(path), offset)
				if err := os.WriteFile(extPath, rawData, 0600); err == nil {
					res.ExtractedTo = extPath
				}
			}

			if jsonOutput || outputPath != "" {
				jsonResults = append(jsonResults, res)
			}
			if !jsonOutput {
				msg := fmt.Sprintf("%s %s [%s]", colorize("[FOUND]", colorGreen), colorize(path, colorBold), reason)
				if offset > 0 {
					msg += fmt.Sprintf(" (Offset: %d)", offset)
				}
				if entropy > 0 {
					msg += fmt.Sprintf(" (Entropy: %.2f)", entropy)
				}
				if res.ExtractedTo != "" {
					msg += fmt.Sprintf("\n    -> %s %s", colorize("Extracted to:", colorYellow), colorize(res.ExtractedTo, colorBold))
				}
				fmt.Println(msg)
			}
		}
		return nil
	})

	if err != nil && !jsonOutput {
		fmt.Printf("%s\n", colorize(fmt.Sprintf("Error during hunt: %v", err), colorRed))
	}

	if !jsonOutput {
		fmt.Printf("\n%s Found %d potential keys/blobs.\n", colorize("[DONE]", colorCyanBold), count)
	}

	// Finalize JSON/File output if needed
	if jsonOutput || outputPath != "" {
		finalizeOutput()
	}
}

func detectKey(path string) (bool, int64, string, float64, []byte) {
	f, err := os.Open(path)
	if err != nil {
		return false, 0, "", 0, nil
	}
	defer f.Close()

	if !stegoScan {
		if !deepHunt {
			buf := make([]byte, 1024)
			n, _ := f.Read(buf)
			if bytes.Contains(buf[:n], []byte("-----BEGIN")) && bytes.Contains(buf[:n], []byte("PRIVATE KEY")) {
				return true, 0, "Standard PEM Header", 0, buf[:n]
			}
			return false, 0, "", 0, nil
		}

		// Deep Mode
		const chunkSize = 4096
		buf := make([]byte, chunkSize)
		var totalRead int64
		for {
			n, err := f.Read(buf)
			if n > 0 {
				if bytes.Contains(buf[:n], []byte("-----BEGIN")) && bytes.Contains(buf[:n], []byte("PRIVATE KEY")) {
					idx := int64(bytes.Index(buf[:n], []byte("-----BEGIN")))
					return true, totalRead + idx, "Embedded PEM Marker", 0, buf[:n]
				}
				totalRead += int64(n)
			}
			if err != nil {
				break
			}
		}
		return false, 0, "", 0, nil
	}

	// Stego Mode
	// Threshold set to 5.8 to reliably catch Base64 material and encrypted chunks
	const blockSize = 256
	buf := make([]byte, blockSize)
	var offset int64
	for {
		n, err := f.Read(buf)
		if n < 64 {
			break
		}
		entropy := calculateChunkEntropy(buf[:n])
		if entropy > 5.8 { 
			return true, offset, "High-Entropy Blob (Base64/Encrypted)", entropy, buf[:n]
		}
		offset += int64(n)
		if err != nil {
			break
		}
	}
	return false, 0, "", 0, nil
}

func calculateChunkEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	frequencies := make(map[byte]float64)
	for _, b := range data {
		frequencies[b]++
	}
	var entropy float64
	for _, count := range frequencies {
		p := count / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func init() {
	rootCmd.AddCommand(huntCmd)
	huntCmd.Flags().BoolVarP(&deepHunt, "deep", "d", false, "Scan full file content for PEM markers")
	huntCmd.Flags().BoolVarP(&stegoScan, "stego", "s", false, "Use entropy analysis to find hidden keys without headers")
	huntCmd.Flags().BoolVarP(&extractBlobs, "extract", "e", false, "Automatically extract and save found keys/blobs to files")
}

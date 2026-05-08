/*
Copyright © 2026 HNCLR by Poyraz Boreas Hancilar
Licensed under the Apache License, Version 2.0
*/
package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

type CleanResult struct {
	FilePath     string `json:"file_path"`
	OutputPath   string `json:"output_path,omitempty"`
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// cleanCmd represents the clean command
var cleanCmd = &cobra.Command{
	Use:   "clean [file/dir]",
	Short: "Deep clean and reconstruct malformed key files",
	Long: `Clean performs forensic reconstruction of a key file. 
It extracts the key payload, strips all hidden whitespace (tabs, spaces, etc.), 
and re-formats the key into a standard 64-character per line PEM block.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(colorize("Error: Please specify file or directory.", colorRed))
			return
		}
		HandlePath(args[0], PerformClean)
	},
}

func PerformClean(filePath string) {
	result := CleanResult{
		FilePath: filePath,
	}

	if !jsonOutput {
		fmt.Printf("%s %s\n", colorize("[CLEANING]", colorCyanBold), filePath)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		result.Status = "Error"
		result.ErrorMessage = fmt.Sprintf("Error reading file: %v", err)
		printCleanResult(result)
		return
	}

	raw := string(content)

	// 1. Regex to capture the header, body, and footer
	re := regexp.MustCompile(`(?s)(-----BEGIN.*?-----)(.*?)(-----END.*?-----)`)
	matches := re.FindStringSubmatch(raw)

	if len(matches) < 4 {
		result.Status = "Error"
		result.ErrorMessage = "Could not find valid BEGIN/END markers in the file."
		printCleanResult(result)
		return
	}

	header := strings.TrimSpace(matches[1])
	body := matches[2]
	footer := strings.TrimSpace(matches[3])

	// 2. Deep Clean
	cleanBody := strings.Map(func(r rune) rune {
		if strings.ContainsRune(" \n\r\t", r) {
			return -1
		}
		return r
	}, body)

	// 3. Re-format
	var finalBody strings.Builder
	for i, r := range cleanBody {
		if i > 0 && i%64 == 0 {
			finalBody.WriteRune('\n')
		}
		finalBody.WriteRune(r)
	}

	// 4. Reconstruction
	finalKey := fmt.Sprintf("%s\n%s\n%s\n", header, finalBody.String(), footer)

	outputPath := filePath + ".cleaned"
	err = os.WriteFile(outputPath, []byte(finalKey), 0600)
	if err != nil {
		result.Status = "Error"
		result.ErrorMessage = fmt.Sprintf("Error writing file: %v", err)
		printCleanResult(result)
		return
	}

	result.Status = "Success"
	result.OutputPath = outputPath
	printCleanResult(result)
}

func printCleanResult(result CleanResult) {
	if jsonOutput || outputPath != "" {
		jsonResults = append(jsonResults, result)
	}

	if jsonOutput {
		return
	}

	if result.Status == "Error" {
		fmt.Printf("%s\n", colorize(result.ErrorMessage, colorRed))
		if strings.Contains(result.ErrorMessage, "BEGIN/END") {
			fmt.Println("Tip: Ensure the file contains a standard header and footer.")
		}
		return
	}

	fmt.Printf("%s\n", colorize(fmt.Sprintf("[OK] Success! Fixed key saved to: %s", result.OutputPath), colorGreen))
	fmt.Printf("Try running: %s %s\n", colorize("keyxray", colorBold), result.OutputPath)
}

func init() {
	rootCmd.AddCommand(cleanCmd)
}

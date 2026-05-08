/*
Copyright © 2026 HNCLR by Poyraz Boreas Hancilar
Licensed under the Apache License, Version 2.0
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var jsonOutput bool
var outputPath string
var isBulkMode bool
var jsonResults []interface{}

const (
	colorReset    = "\033[0m"
	colorRed      = "\033[31m"
	colorGreen    = "\033[32m"
	colorYellow   = "\033[33m"
	colorCyanBold = "\033[1;36m"
	colorBold     = "\033[1m"
)

func colorize(text, colorCode string) string {
	if jsonOutput {
		return text
	}
	return colorCode + text + colorReset
}

func HandlePath(path string, action func(string)) {
	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if !info.IsDir() {
		action(path)
	} else {
		isBulkMode = true
		err = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				data, err := os.ReadFile(p)
				if err == nil && strings.Contains(string(data), "-----BEGIN") {
					if !jsonOutput {
						fmt.Printf("\n%s %s\n", colorize("===> PROCESSING:", colorCyanBold), colorize(p, colorBold))
					}
					action(p)
				}
			}
			return nil
		})

		if err != nil {
			fmt.Printf("Error walking path: %v\n", err)
		}
	}

	finalizeOutput()
}

func finalizeOutput() {
	if len(jsonResults) == 0 {
		return
	}

	var data []byte
	if isBulkMode || len(jsonResults) > 1 {
		data, _ = json.MarshalIndent(jsonResults, "", "  ")
	} else {
		data, _ = json.MarshalIndent(jsonResults[0], "", "  ")
	}

	if jsonOutput {
		fmt.Println(string(data))
	}

	if outputPath != "" {
		err := os.WriteFile(outputPath, data, 0644)
		if err != nil {
			msg := fmt.Sprintf("\n%s Failed to save report: %v\n", colorize("[ERROR]", colorRed), err)
			if jsonOutput {
				fmt.Fprint(os.Stderr, colorRed+msg+colorReset)
			} else {
				fmt.Print(msg)
			}
		} else {
			msg := fmt.Sprintf("\n%s Report saved to %s\n", "[OK]", outputPath)
			if jsonOutput {
				// Always use green for the success message even if jsonOutput is true, but send to Stderr
				fmt.Fprint(os.Stderr, colorGreen+msg+colorReset)
			} else {
				fmt.Print(colorGreen + msg + colorReset)
			}
		}
	}
}

var rootCmd = &cobra.Command{
	Use:   "keyxray [command] [file/dir] [flags]",
	Short: "SSH Key Forensic and Audit Tool",
	Long: `KeyXray is a high-performance forensic tool for SSH key analysis. 
It specializes in rescuing malformed keys, auditing security posture, 
and managing large-scale key collections through advanced matching 
and hunting algorithms.`,
	Args: cobra.ArbitraryArgs,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			HandlePath(args[0], func(p string) {
				PerformInspect(p)
				PerformAudit(p)
			})
		} else {
			cmd.Help()
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", false, "Output in JSON format")
	rootCmd.PersistentFlags().StringVarP(&outputPath, "output", "o", "", "Save JSON output to specified file")

	// Custom Colorized Help Template
	rootCmd.SetHelpTemplate(fmt.Sprintf(`
%s
  KeyXray - Copyright (c) 2026 HNCLR by Poyraz Boreas Hancilar
  Licensed under the Apache License, Version 2.0

%s
  KeyXray is a high-performance forensic tool for SSH key analysis. 
  It specializes in rescuing malformed keys, auditing security posture, 
  and managing large-scale key collections through advanced matching 
  and hunting algorithms.

%s
  keyxray [command] [file/dir] [flags]

%s{{if .HasAvailableSubCommands}}
  {{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
    %s {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

%s
  {{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

%s
  {{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

%s
  {{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
    {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`,
		colorize("IDENTITY", colorCyanBold),
		colorize("DESCRIPTION", colorCyanBold),
		colorize("USAGE", colorCyanBold),
		colorize("COMMANDS", colorCyanBold),
		colorize("{{rpad .Name .NamePadding}}", colorBold),
		colorize("FLAGS", colorCyanBold),
		colorize("GLOBAL FLAGS", colorCyanBold),
		colorize("ADDITIONAL HELP", colorCyanBold),
	))
}

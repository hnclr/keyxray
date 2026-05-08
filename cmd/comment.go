/*
Copyright © 2026 HNCLR by Poyraz Boreas Hancilar
Licensed under the Apache License, Version 2.0
*/
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var newComment string

var commentCmd = &cobra.Command{
	Use:   "comment [file.pub]",
	Short: "View or set the comment of a public key",
	Long:  `Comment command reads a public key (.pub) and allows you to view or change its trailing comment string.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(colorize("Error: Please specify a public key (.pub) file.", colorRed))
			return
		}
		PerformComment(args[0], newComment)
	},
}

func PerformComment(filePath, comment string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("%s Error reading file: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	pubKey, existingComment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		fmt.Printf("%s Error parsing public key: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	fmt.Printf("%s File: %s\n", colorize("[PUBLIC KEY COMMENT]", colorCyanBold), filePath)
	fmt.Printf("Current Comment : %s\n", colorize(existingComment, colorBold))

	if comment != "" {
		newKeyString := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey))) + " " + comment + "\n"

		err = os.WriteFile(filePath, []byte(newKeyString), 0644)
		if err != nil {
			fmt.Printf("%s Error updating comment: %v\n", colorize("[ERROR]", colorRed), err)
			return
		}
		fmt.Printf("%s Comment updated to: %s\n", colorize("[OK]", colorGreen), colorize(comment, colorBold))
	}
}

func init() {
	rootCmd.AddCommand(commentCmd)
	commentCmd.Flags().StringVarP(&newComment, "set", "s", "", "Set a new comment for the public key")
}

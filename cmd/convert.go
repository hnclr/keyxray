/*
Copyright © 2026 HNCLR by Poyraz Boreas Hancilar
Licensed under the Apache License, Version 2.0
*/
package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var convertFormat string

var convertCmd = &cobra.Command{
	Use:   "convert [file]",
	Short: "Convert a private key to a specific format",
	Long:  `Convert reads a private key and rewrites it in a specified PEM format (pkcs1 or pkcs8).`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(colorize("Error: Please specify a private key file.", colorRed))
			return
		}
		PerformConvert(args[0], convertFormat)
	},
}

func PerformConvert(filePath, format string) {
	fmt.Printf("%s File: %s to %s\n", colorize("[CONVERTING]", colorCyanBold), filePath, format)

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("%s Error reading file: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		fmt.Printf("%s Error parsing key: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	var pemBlock *pem.Block

	switch format {
	case "pkcs1":
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			fmt.Printf("%s PKCS#1 format is only applicable to RSA keys.\n", colorize("[ERROR]", colorRed))
			return
		}
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}
	case "pkcs8":
		bytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			fmt.Printf("%s Error marshaling to PKCS#8: %v\n", colorize("[ERROR]", colorRed), err)
			return
		}
		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		}
	default:
		fmt.Printf("%s Unsupported format: %s. Use 'pkcs1' or 'pkcs8'.\n", colorize("[ERROR]", colorRed), format)
		return
	}

	outPath := filePath + "." + format
	err = os.WriteFile(outPath, pem.EncodeToMemory(pemBlock), 0600)
	if err != nil {
		fmt.Printf("%s Error saving file: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	fmt.Printf("%s Converted key saved to: %s\n", colorize("[OK]", colorGreen), colorize(outPath, colorBold))
}

func init() {
	rootCmd.AddCommand(convertCmd)
	convertCmd.Flags().StringVarP(&convertFormat, "format", "f", "pkcs8", "Target format: pkcs1 or pkcs8")
}

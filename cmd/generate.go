/*
Copyright © 2026 HNCLR by Poyraz Boreas Hancilar
Licensed under the Apache License, Version 2.0
*/
package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var genName string
var genType string

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new secure SSH key pair",
	Long:  `Generate creates a new SSH private and public key pair (ED25519 or RSA).`,
	Run: func(cmd *cobra.Command, args []string) {
		PerformGenerate(genName, genType)
	},
}

func PerformGenerate(name, kType string) {
	fmt.Printf("%s Generating %s key pair: %s\n", colorize("[GENERATING]", colorCyanBold), kType, name)

	var privKey interface{}
	var err error

	switch kType {
	case "ed25519":
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	case "rsa":
		privKey, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		fmt.Printf("%s Unsupported type: %s. Use 'ed25519' or 'rsa'.\n", colorize("[ERROR]", colorRed), kType)
		return
	}

	if err != nil {
		fmt.Printf("%s Error generating key: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	// Encode private key
	privBytes, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		fmt.Printf("%s Error marshaling private key: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	err = os.WriteFile(name, pem.EncodeToMemory(privBytes), 0600)
	if err != nil {
		fmt.Printf("%s Error saving private key: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	// Encode public key
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		fmt.Printf("%s Error creating signer: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	pubKey := signer.PublicKey()
	pubBytes := ssh.MarshalAuthorizedKey(pubKey)

	err = os.WriteFile(name+".pub", pubBytes, 0644)
	if err != nil {
		fmt.Printf("%s Error saving public key: %v\n", colorize("[ERROR]", colorRed), err)
		return
	}

	fmt.Printf("%s Key pair generated successfully!\n", colorize("[OK]", colorGreen))
	fmt.Printf("Private : %s (0600)\n", colorize(name, colorBold))
	fmt.Printf("Public  : %s (0644)\n", name+".pub")
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVarP(&genName, "name", "n", "id_keyxray", "Name of the key file")
	generateCmd.Flags().StringVarP(&genType, "type", "t", "ed25519", "Key type: ed25519 or rsa")
}

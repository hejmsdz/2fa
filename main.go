package main

import (
	"fmt"
	"os"
	"path"

	"github.com/99designs/keyring"
	"github.com/atotto/clipboard"
)

func GetPassword() (string, error) {
	keyring, err := keyring.Open(keyring.Config{
		ServiceName:              "2FA",
		KeychainTrustApplication: true,
	})

	if err != nil {
		return "", err
	}

	keys, err := keyring.Keys()

	if err != nil || len(keys) < 1 {
		return "", err
	}

	entry, err := keyring.Get(keys[0])

	if err != nil {
		return "", err
	}

	return string(entry.Data), nil
}

func main() {
	password, err := GetPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get the encryption password: %s\n", err)
		return
	}

	home, _ := os.UserHomeDir()
	filename := path.Join(home, ".2fa", "otp_accounts.json.aes")
	accounts, err := ReadDatabase(filename, password)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open your database: %s\n", err)
		return
	}

	if len(os.Args) < 2 {
		fmt.Println("Available accounts:")
		for _, entry := range accounts {
			fmt.Printf("* %s\n", entry.Label)
		}
		return
	}

	label := os.Args[1]
	entry := FindAccountByLabel(accounts, label)

	if entry == nil {
		fmt.Fprintf(os.Stderr, "No matching account found\n")
		return
	}

	otp := Totp(entry.Secret, entry.Period, entry.Digits)
	fmt.Printf("2FA code for %s: %s\n", entry.Label, otp)

	err = clipboard.WriteAll(otp)
	if err == nil {
		fmt.Println("(copied to clipboard)")
	}
}

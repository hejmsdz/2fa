package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type Account struct {
	Secret string `json:"secret"`
	Label  string `json:"label"`
	Digits uint   `json:"digits"`
	Period uint   `json:"period"`
	Type   string `json:"type"`
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func ReadRawFile(filename string) (uint32, []byte, []byte, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return 0, nil, nil, err
	}

	iterations := binary.BigEndian.Uint32(bytes[0:4])
	salt := bytes[4:16]
	encryptedData := bytes[16:]

	return iterations, salt, encryptedData, nil
}

func ReadDatabase(filename string, password string) ([]Account, error) {
	iterations, salt, encryptedData, err := ReadRawFile(filename)
	if err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(password), salt, int(iterations), 32, sha1.New)
	data, err := decrypt(encryptedData, key)
	if err != nil {
		return nil, err
	}

	accounts := make([]Account, 0)
	json.NewDecoder(strings.NewReader(string(data))).Decode(&accounts)

	return accounts, nil
}

func FindAccountByLabel(accounts []Account, label string) *Account {
	labelLower := strings.ToLower(label)
	for _, entry := range accounts {
		if strings.Contains(strings.ToLower(entry.Label), labelLower) {
			return &entry
		}
	}
	return nil
}

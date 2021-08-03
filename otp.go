package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"strings"
	"time"
)

func truncate(hash []byte) int {
	offset := int(hash[19] & 0xF)
	return int(hash[offset]&0x7F)<<24 | int(hash[offset+1]&0xFF)<<16 | int(hash[offset+2]&0xFF)<<8 | int(hash[offset+3]&0xFF)
}

func powerOf10(n uint) int {
	res := 1
	for i := uint(0); i < n; i++ {
		res *= 10
	}
	return res
}

func Hotp(secret string, counter uint64, digits uint) string {
	b32 := base32.NewDecoder(base32.StdEncoding, strings.NewReader(secret))
	secretBytes, _ := ioutil.ReadAll(b32)
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, counter)

	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(countBytes)
	hash := mac.Sum(nil)
	codeNumber := truncate(hash) % powerOf10(digits)

	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, codeNumber)
}

func TotpAtTime(secret string, time time.Time, period uint, digits uint) string {
	counter := uint64(time.Unix()) / uint64(period)
	return Hotp(secret, counter, digits)
}

func Totp(secret string, period uint, digits uint) string {
	return TotpAtTime(secret, time.Now(), period, digits)
}

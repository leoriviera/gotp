package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"net/url"
	"os/user"
	"time"
)

type Algorithm string

const (
	SHA1 = "SHA1"
	SHA256 = "SHA256"
	SHA512 = "SHA512"
)

var secretLength = map[Algorithm]int{
	SHA1: 20,
	SHA256: 32,
	SHA512: 64,
}

var digitsPower = map[int]uint32{
	6: 1_000_000,
	8: 100_000_000,
}

var period = uint64(30)

func generateHMAC(secret, counter []byte, mode Algorithm) []byte {
	var mac hash.Hash

	if mode == SHA1 {
		mac = hmac.New(sha1.New, secret)
	} else if mode == SHA256 {
		mac = hmac.New(sha256.New, secret)
	} else if mode == SHA512 {
		mac = hmac.New(sha512.New, secret)
	}

	mac.Write(counter)
	return mac.Sum(nil)
}

func dynamicTruncate(hmac []byte) []byte {
	offset := hmac[len(hmac) - 1] & 0xf
	dbc := hmac[offset:offset+4]
	dbc[0] = dbc[0] & 0x7f
	return dbc
}

func generateSecret(algorithm Algorithm) []byte {
	length := secretLength[algorithm]
	secret := make([]byte, length)

	charRangeStart := 65
	charRangeEnd := 122
	charRange := int64((charRangeEnd - charRangeStart) + 1)

	for i := range secret {
		n, err := rand.Int(rand.Reader, big.NewInt(charRange))

		if err != nil {
			panic(err)
		}

		secret[i] = byte(n.Int64() + 65)
	}

	return secret
}

func generateHOTP(secret, counter []byte, length int, algorithm Algorithm) string {
	hmac := generateHMAC(secret, counter, algorithm)
	truncated_hmac := dynamicTruncate(hmac)

	// Dynamically create format string, depending on length of HOTP code
	// TODO - Consider using fmt.FormatString?
	hotp := fmt.Sprintf(fmt.Sprintf("%%0%dd", length), binary.BigEndian.Uint32(truncated_hmac) % digitsPower[length])
	return hotp
}

func generateTOTP(secret []byte, unixSeconds int64, length int, algorithm Algorithm) string {
	counter := make([]byte, 8)
	elapsedSteps := uint64(unixSeconds) / period
	binary.BigEndian.PutUint64(counter, elapsedSteps)

	return generateHOTP(secret, counter, length, algorithm)
}

func createOTPURI(secret []byte, algorithm Algorithm) string {
	user, err := user.Current()

	if err != nil {
		panic(err)
	}

	queryParms := url.Values {
		"algorithm": { string(algorithm) },
		"digits": { "6" },
		"issuer": { "gotp" },
		"period": { fmt.Sprintf("%d", period) },
		"secret": { base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret) },
	}

	url := url.URL {
		Scheme: "otpauth",
		Host: "totp",
		Path: fmt.Sprintf("gotp:%v", user.Name),
		RawQuery: queryParms.Encode(),
	}

	return url.String()
}

func main() {
	var algorithm Algorithm = SHA256

	secret := generateSecret(algorithm)

	fmt.Printf("Create a QR code using the following URI, and add it to an OTP auth app:\n%v\n\n", createOTPURI(secret, algorithm))

	var code string

	for {
		fmt.Print("Enter a TOTP code\n> ")
		fmt.Scanln(&code)
		fmt.Printf("%v\n", code)

		unixSeconds := time.Now().Unix()

		totp := generateTOTP(secret, unixSeconds, 8, algorithm)

		if totp == code {
			fmt.Printf("code correct\n")
		} else {
			fmt.Printf("code incorrect\ngot %s, want %s\n", code, totp)
		}

		fmt.Print("\n")
	}
}

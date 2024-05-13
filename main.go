package main

import (
	"fmt"
	"time"
)

type Algorithm string
type Digits int
type Period uint64

const (
	SHA1 = "SHA1"
	SHA256 = "SHA256"
	SHA512 = "SHA512"
)

var issuer = "leoriviera.gotp"

func main() {
	var algorithm Algorithm = SHA1

	totp := NewTOTP(algorithm, 6, 30)

	fmt.Printf("Create a QR code using the following URI, and add it to an OTP auth app:\n%v\n\n", totp.GenerateURI())

	var input string

	for {
		fmt.Print("Enter a TOTP code\n> ")
		fmt.Scanln(&input)
		fmt.Printf("%v\n", input)

		seconds := time.Now().Unix()

		code := totp.GenerateOTP(seconds)

		if code == input {
			fmt.Printf("code correct\n")
		} else {
			fmt.Printf("code incorrect\ngot %s, want %s\n", input, code)
		}

		fmt.Print("\n")
	}
}

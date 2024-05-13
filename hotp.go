package main

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"os/user"
)

type hotp struct {
	algorithm Algorithm
	digits Digits
	secret []byte
}

var digitsPower = map[Digits]uint32{
	6: 1_000_000,
	8: 100_000_000,
}

func NewHOTP(algorithm Algorithm, digits Digits) *hotp {
	secret := generateSecret(algorithm)

	return &hotp {
		algorithm,
		digits,
		secret,
	}
}

func (h *hotp) Algorithm() Algorithm {
	return h.algorithm
}

func (h *hotp) Secret() []byte {
	return h.secret
}

// TODO - implement
func (h *hotp) GenerateURI() string {
	user, err := user.Current()

	if err != nil {
		panic(err)
	}

	queryParms := url.Values {
		"algorithm": { string(h.algorithm) },
		"digits": { fmt.Sprintf("%d", h.digits) },
		"issuer": { issuer },
		"counter": { fmt.Sprintf("%d", 0) },
		"secret": { base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.secret) },
	}

	url := url.URL {
		Scheme: "otpauth",
		Host: "hotp",
		Path: fmt.Sprintf("%s:%s", issuer, user.Name),
		RawQuery: queryParms.Encode(),
	}

	return url.String()
}

func (h *hotp) GenerateOTP(counter uint64) string {
	hmac := generateHMAC(h, convertCounterToBytes(counter))
	truncated_hmac := dynamicTruncate(hmac)

	// Dynamically create format string, depending on length of HOTP code
	// TODO - Consider using fmt.FormatString?
	otp := fmt.Sprintf(fmt.Sprintf("%%0%dd", h.digits), binary.BigEndian.Uint32(truncated_hmac) % digitsPower[h.digits])

	return otp
}

func (h *hotp) ValidateOTP(counter uint64, otp string) bool {
	return h.GenerateOTP(counter) == otp
}

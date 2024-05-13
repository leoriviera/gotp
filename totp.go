package main

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"os/user"
)

type totp struct {
	algorithm Algorithm
	digits Digits
	period Period
	secret []byte
}

func NewTOTP(algorithm Algorithm, digits Digits, period Period) *totp {
	secret := generateSecret(algorithm)

	return &totp {
		algorithm,
		digits,
		period,
		secret,
	}
}

func (t *totp) Algorithm() Algorithm {
	return t.algorithm
}

func (t *totp) Secret() []byte {
	return t.secret
}

// TODO - implement
func (t *totp) GenerateURI() string {
	user, err := user.Current()

	if err != nil {
		panic(err)
	}

	queryParms := url.Values {
		"algorithm": { string(t.algorithm) },
		"digits": { fmt.Sprintf("%d", t.digits) },
		"issuer": { issuer },
		"period": { fmt.Sprintf("%d", t.period) },
		"secret": { base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.secret) },
	}

	url := url.URL {
		Scheme: "otpauth",
		Host: "totp",
		Path: fmt.Sprintf("%s:%s", issuer, user.Name),
		RawQuery: queryParms.Encode(),
	}

	return url.String()
}

func (t *totp) GenerateOTP(seconds int64) string {
	steps := uint64(seconds) / uint64(t.period)
	return t.toHOTP().GenerateOTP(steps)
}

func (t *totp) ValidateOTP(seconds int64, otp string) bool {
	return t.GenerateOTP(seconds) == otp
}

func (t* totp) toHOTP() *hotp {
	return &hotp {
		algorithm: t.algorithm,
		digits: t.digits,
		secret: t.secret,
	}
}

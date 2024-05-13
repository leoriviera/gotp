package main

import (
	"fmt"
	"testing"
)

func TestTOTP(t *testing.T) {
	lengths := [2]int{ 6, 8 }

	var tests = []struct {
		secret string
		time int64
		algorithm Algorithm
		code string
	}{
		{"12345678901234567890", 59, SHA1, "94287082"},
		{"12345678901234567890123456789012", 59, SHA256, "46119246"},
		{"1234567890123456789012345678901234567890123456789012345678901234", 59, SHA512, "90693936"},
		{"12345678901234567890", 1111111109, SHA1, "07081804"},
		{"12345678901234567890123456789012", 1111111109, SHA256, "68084774"},
		{"1234567890123456789012345678901234567890123456789012345678901234", 1111111109, SHA512, "25091201"},
		{"12345678901234567890", 1111111111, SHA1, "14050471"},
		{"12345678901234567890123456789012", 1111111111, SHA256, "67062674"},
		{"1234567890123456789012345678901234567890123456789012345678901234", 1111111111, SHA512, "99943326"},
		{"12345678901234567890", 1234567890, SHA1, "89005924"},
		{"12345678901234567890123456789012", 1234567890, SHA256, "91819424"},
		{"1234567890123456789012345678901234567890123456789012345678901234", 1234567890, SHA512, "93441116"},
		{"12345678901234567890", 2000000000, SHA1, "69279037"},
		{"12345678901234567890123456789012", 2000000000, SHA256, "90698825"},
		{"1234567890123456789012345678901234567890123456789012345678901234", 2000000000, SHA512, "38618901"},
		{"12345678901234567890", 20000000000, SHA1, "65353130"},
		{"12345678901234567890123456789012", 20000000000, SHA256, "77737706"},
		{"1234567890123456789012345678901234567890123456789012345678901234", 20000000000, SHA512, "47863826"},
	}

	for _, tt := range tests {
		for _, digits := range lengths  {
			testname := fmt.Sprintf("time:%d,digits:%d,algorithm:%s", tt.time, digits, tt.algorithm)

			t.Run(testname, func(t *testing.T) {
				totp := &totp{
					algorithm: tt.algorithm,
					digits: Digits(digits),
					period: 30,
					secret: []byte(tt.secret),
				}

				code := totp.GenerateOTP(tt.time)

				// Get last [digits] digits from tt.totp
				expectedTOTP := tt.code[len(tt.code)-digits:]

				if code != expectedTOTP {
					t.Errorf("got %s, want %s", code, expectedTOTP)
				}
			})
		}
	}
}

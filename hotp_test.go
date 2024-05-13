package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestGenerateIntermediateHMACValue(t *testing.T) {
	var secret = []byte("12345678901234567890")

	var tests = []struct {
		counterValue uint64
		hmac         string
	}{
		{0, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0"},
		{1, "75a48a19d4cbe100644e8ac1397eea747a2d33ab"},
		{2, "0bacb7fa082fef30782211938bc1c5e70416ff44"},
		{3, "66c28227d03a2d5529262ff016a1e6ef76557ece"},
		{4, "a904c900a64b35909874b33e61c5938a8e15ed1c"},
		{5, "a37e783d7b7233c083d4f62926c7a25f238d0316"},
		{6, "bc9cd28561042c83f219324d3c607256c03272ae"},
		{7, "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa"},
		{8, "1b3c89f65e6c9e883012052823443f048b4332db"},
		{9, "1637409809a679dc698207310c8c7fc07290d9e5"},
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("counter:%d", tt.counterValue)
		t.Run(testname, func(t *testing.T) {
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, tt.counterValue)

			hotp := &hotp{
				algorithm: SHA1,
				digits: 6,
				secret: secret,
			}
			hmac := hex.EncodeToString(generateHMAC(hotp, counter))

			if hmac != tt.hmac {
				t.Errorf("got %s, want %s", hmac, tt.hmac)
			}
		})
	}
}


func TestTruncatedHMACValue(t *testing.T) {
	var secret = []byte("12345678901234567890")

	var tests = []struct {
		counterValue uint64
		truncated    string
	}{
		{0, "4c93cf18"},
		{1, "41397eea"},
		{2, "082fef30"},
		{3, "66ef7655"},
		{4, "61c5938a"},
		{5, "33c083d4"},
		{6, "7256c032"},
		{7, "04e5b397"},
		{8, "2823443f"},
		{9, "2679dc69"},
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("counter:%d", tt.counterValue)
		t.Run(testname, func(t *testing.T) {
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, tt.counterValue)

			hotp := &hotp{
				algorithm: SHA1,
				digits: 6,
				secret: secret,
			}
			hmac := generateHMAC(hotp, counter)
			truncated := hex.EncodeToString(dynamicTruncate(hmac))

			if truncated != tt.truncated {
				t.Errorf("got %s, want %s", truncated, tt.truncated)
			}
		})
	}
}

func TestHOTP(t *testing.T) {
	var secret = []byte("12345678901234567890")

	var tests = []struct {
		counterValue uint64
		code         string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("counter:%d", tt.counterValue)
		t.Run(testname, func(t *testing.T) {
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, tt.counterValue)

			hotp := &hotp{
				algorithm: SHA1,
				digits: 6,
				secret: secret,
			}

			code := hotp.GenerateOTP(tt.counterValue)

			if code != tt.code {
				t.Errorf("got %s, want %s", code, tt.code)
			}
		})
	}
}

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"math/big"
)

var secretLength = map[Algorithm]int{
	SHA1: 20,
	SHA256: 32,
	SHA512: 64,
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

func dynamicTruncate(hmac []byte) []byte {
	offset := hmac[len(hmac) - 1] & 0xf
	dbc := hmac[offset:offset+4]
	dbc[0] = dbc[0] & 0x7f
	return dbc
}


func generateHMAC[V OTP](o V, counter []byte) []byte {
	var mac hash.Hash

	if o.Algorithm() == SHA1 {
		mac = hmac.New(sha1.New, o.Secret())
	} else if o.Algorithm() == SHA256 {
		mac = hmac.New(sha256.New, o.Secret())
	} else if o.Algorithm() == SHA512 {
		mac = hmac.New(sha512.New, o.Secret())
	}

	mac.Write(counter)
	return mac.Sum(nil)
}

func convertCounterToBytes(c uint64) []byte {
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, c)
	return counter
}

package main

type OTP interface {
	Algorithm() Algorithm
	Secret() []byte
	GenerateURI() string
}

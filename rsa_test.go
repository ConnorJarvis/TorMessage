package main

import (
	"crypto/rand"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	e := NewRSA()
	_, _, err := e.GenerateRSAKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e := NewRSA()
		_, _, err := e.GenerateRSAKey(rand.Reader)
		if err != nil {
			b.Error(err)
		}
	}
}

func TestSignMessage(t *testing.T) {
	e := NewRSA()
	privateKey, _, err := e.GenerateRSAKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	message := MessageEncrypted{
		ID:      1,
		Header:  []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101},
		Message: []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101},
	}
	_, err = e.SignMessage(rand.Reader, *privateKey, message)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkSignMessage(b *testing.B) {
	e := NewRSA()
	privateKey, _, err := e.GenerateRSAKey(rand.Reader)
	if err != nil {
		b.Error(err)
	}
	message := MessageEncrypted{
		ID:      1,
		Header:  []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101},
		Message: []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101},
	}
	for i := 0; i < b.N; i++ {
		_, err = e.SignMessage(rand.Reader, *privateKey, message)
		if err != nil {
			b.Error(err)
		}
	}
}

func TestVerifyMessage(t *testing.T) {
	e := NewRSA()
	privateKey, publicKey, err := e.GenerateRSAKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	message := MessageEncrypted{
		ID:      1,
		Header:  []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101},
		Message: []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101},
	}
	signedMessage, err := e.SignMessage(rand.Reader, *privateKey, message)
	if err != nil {
		t.Error(err)
	}
	err = e.VerifyMessage(rand.Reader, *publicKey, *signedMessage)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkVerifyMessage(b *testing.B) {
	e := NewRSA()
	privateKey, publicKey, err := e.GenerateRSAKey(rand.Reader)
	if err != nil {
		b.Error(err)
	}
	message := MessageEncrypted{
		ID:      1,
		Header:  []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101},
		Message: []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101},
	}
	signedMessage, err := e.SignMessage(rand.Reader, *privateKey, message)
	if err != nil {
		b.Error(err)
	}
	for i := 0; i < b.N; i++ {
		err = e.VerifyMessage(rand.Reader, *publicKey, *signedMessage)
		if err != nil {
			b.Error(err)
		}
	}
}

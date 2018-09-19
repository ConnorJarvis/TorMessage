package main

import (
	"crypto/rand"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	e := NewRSA()
	_, _, err := e.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e := NewRSA()
		_, _, err := e.GenerateKey(rand.Reader)
		if err != nil {
			b.Error(err)
		}
	}
}

func TestSignMessage(t *testing.T) {
	e := NewRSA()
	privateKey, _, err := e.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	_, err = e.SignMessage(rand.Reader, *privateKey, Message{ID: 1, Message: []byte("test")})
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkSignMessage(b *testing.B) {
	e := NewRSA()
	privateKey, _, err := e.GenerateKey(rand.Reader)
	if err != nil {
		b.Error(err)
	}
	for i := 0; i < b.N; i++ {
		_, err = e.SignMessage(rand.Reader, *privateKey, Message{ID: 1, Message: []byte("test")})
		if err != nil {
			b.Error(err)
		}
	}
}

func TestVerifyMessage(t *testing.T) {
	e := NewRSA()
	privateKey, publicKey, err := e.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	message, err := e.SignMessage(rand.Reader, *privateKey, Message{ID: 1, Message: []byte("test")})
	if err != nil {
		t.Error(err)
	}
	err = e.VerifyMessage(rand.Reader, *publicKey, *message)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkVerifyMessage(b *testing.B) {
	e := NewRSA()
	privateKey, publicKey, err := e.GenerateKey(rand.Reader)
	if err != nil {
		b.Error(err)
	}
	message, err := e.SignMessage(rand.Reader, *privateKey, Message{ID: 1, Message: []byte("test")})
	if err != nil {
		b.Error(err)
	}
	for i := 0; i < b.N; i++ {
		err = e.VerifyMessage(rand.Reader, *publicKey, *message)
		if err != nil {
			b.Error(err)
		}
	}
}

package main

import (
	"crypto/rand"
	"reflect"
	"testing"
)

func TestEncrypt(t *testing.T) {
	e := NewAES()
	message := []byte{116, 101, 115, 116}
	key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
	nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
	cipherText, err := e.Encrypt(message, key, nonce)
	if err != nil {
		t.Error(err)
	}
	expectedCipher := []byte{227, 205, 185, 41, 153, 220, 30, 68, 85, 252, 181, 221, 52, 61, 99, 223, 21, 147, 176, 239}
	if !reflect.DeepEqual(cipherText, expectedCipher) {
		t.Error("encryption failed")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e := NewAES()
		message := []byte{116, 101, 115, 116}
		key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
		nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
		cipherText, err := e.Encrypt(message, key, nonce)
		if err != nil {
			b.Error(err)
		}
		expectedCipher := []byte{227, 205, 185, 41, 153, 220, 30, 68, 85, 252, 181, 221, 52, 61, 99, 223, 21, 147, 176, 239}
		if !reflect.DeepEqual(cipherText, expectedCipher) {
			b.Error("encryption failed")
		}
	}
}

func TestDecrypt(t *testing.T) {
	e := NewAES()
	cipherText := []byte{227, 205, 185, 41, 153, 220, 30, 68, 85, 252, 181, 221, 52, 61, 99, 223, 21, 147, 176, 239}
	key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
	nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
	message, err := e.Decrypt(cipherText, key, nonce)
	if err != nil {
		t.Error(err)
	}
	expectedMessage := []byte{116, 101, 115, 116}
	if !reflect.DeepEqual(message, expectedMessage) {
		t.Error("decryption failed")
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e := NewAES()
		cipherText := []byte{227, 205, 185, 41, 153, 220, 30, 68, 85, 252, 181, 221, 52, 61, 99, 223, 21, 147, 176, 239}
		key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
		nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
		message, err := e.Decrypt(cipherText, key, nonce)
		if err != nil {
			b.Error(err)
		}
		expectedMessage := []byte{116, 101, 115, 116}
		if !reflect.DeepEqual(message, expectedMessage) {
			b.Error("decryption failed")
		}
	}
}

func TestGenerateAESKey(t *testing.T) {
	e := NewAES()
	_, err := e.GenerateAESKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkGenerateAESKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e := NewAES()
		_, err := e.GenerateAESKey(rand.Reader)
		if err != nil {
			b.Error(err)
		}
	}
}

func TestGenerateAESNonce(t *testing.T) {
	e := NewAES()
	_, err := e.GenerateAESNonce(rand.Reader)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkGenerateAESNonce(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e := NewAES()
		_, err := e.GenerateAESNonce(rand.Reader)
		if err != nil {
			b.Error(err)
		}
	}
}

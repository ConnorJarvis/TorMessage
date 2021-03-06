package tormessage

import (
	"crypto/rand"
	"fmt"
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

func TestEncryptHeader(t *testing.T) {
	e := NewAES()
	header := &Header{
		MessageType:    1,
		MessageVersion: 1,
		Hostname:       "example.com",
	}
	key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
	nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
	cipherText, err := e.EncryptHeader(*header, key, nonce)
	if err != nil {
		t.Error(err)
	}
	expectedCipherText := []byte{211, 87, 75, 94, 222, 79, 81, 63, 244, 37, 211, 238, 130, 102, 16, 94, 67, 16, 101, 131, 136, 246, 93, 131, 113, 152, 215, 90, 160, 32, 73, 166, 236, 179, 53, 80, 50, 143, 112, 32, 213, 133, 85, 57, 73, 233, 54, 91, 230, 5, 84, 242, 95, 73, 38, 170, 12, 212, 112, 155, 153, 87, 14, 38, 9, 78, 183, 179, 50, 76, 145, 69, 52, 208, 125, 2, 217, 68, 127, 206, 27, 22, 0, 27, 206, 39, 152, 178, 37, 78, 164, 123, 166, 55, 197, 49, 176, 142, 128, 85, 189, 220, 243, 181, 195, 244}

	if !reflect.DeepEqual(cipherText, expectedCipherText) {
		t.Error("header encryption failed")
	}
}

func BenchmarkEncryptHeader(b *testing.B) {
	e := NewAES()
	header := &Header{
		MessageType:    1,
		MessageVersion: 1,
		Hostname:       "example.com",
	}
	key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
	nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
	expectedCipherText := []byte{211, 87, 75, 94, 222, 79, 81, 63, 244, 37, 211, 238, 130, 102, 16, 94, 67, 16, 101, 131, 136, 246, 93, 131, 113, 152, 215, 90, 160, 32, 73, 166, 236, 179, 53, 80, 50, 143, 112, 32, 213, 133, 85, 57, 73, 233, 54, 91, 230, 5, 84, 242, 95, 73, 38, 170, 12, 212, 112, 155, 153, 87, 14, 38, 9, 78, 183, 179, 50, 76, 145, 69, 52, 208, 125, 2, 217, 68, 127, 206, 27, 22, 0, 27, 206, 39, 152, 178, 37, 78, 164, 123, 166, 55, 197, 49, 176, 142, 128, 85, 189, 220, 243, 181, 195, 244}
	for i := 0; i < b.N; i++ {
		cipherText, err := e.EncryptHeader(*header, key, nonce)
		if err != nil {
			b.Error(err)
		}

		if !reflect.DeepEqual(cipherText, expectedCipherText) {
			b.Error("header encryption failed")
		}
	}
}

func TestDecryptHeader(t *testing.T) {
	e := NewAES()
	testHeader := Header{
		MessageType:    1,
		MessageVersion: 1,
		Hostname:       "example.com",
	}
	key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
	nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
	cipherText := []byte{211, 87, 75, 94, 222, 79, 81, 63, 244, 37, 211, 238, 130, 102, 16, 94, 67, 16, 101, 131, 136, 246, 93, 131, 113, 152, 215, 90, 160, 32, 73, 166, 236, 179, 53, 80, 50, 143, 112, 32, 213, 133, 85, 57, 73, 233, 54, 91, 230, 5, 84, 242, 95, 73, 38, 170, 12, 212, 112, 155, 153, 87, 14, 38, 9, 78, 183, 179, 50, 76, 145, 69, 52, 208, 125, 2, 217, 68, 127, 206, 27, 22, 0, 27, 206, 39, 152, 178, 37, 78, 164, 123, 166, 55, 197, 49, 176, 142, 128, 85, 189, 220, 243, 181, 195, 244}

	header, err := e.DecryptHeader(cipherText, key, nonce)

	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(*header, testHeader) {
		t.Error("header decryption failed")
	}
}

func BenchmarkDecryptHeader(b *testing.B) {
	e := NewAES()
	testHeader := &Header{
		MessageType:    1,
		MessageVersion: 1,
		Hostname:       "example.com",
	}
	key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
	nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
	cipherText := []byte{211, 87, 75, 94, 222, 79, 81, 63, 244, 37, 211, 238, 130, 102, 16, 94, 67, 16, 101, 131, 136, 246, 93, 131, 113, 152, 215, 90, 160, 32, 73, 166, 236, 179, 53, 80, 50, 143, 112, 32, 213, 133, 85, 57, 73, 233, 54, 91, 230, 5, 84, 242, 95, 73, 38, 170, 12, 212, 112, 155, 153, 87, 14, 38, 9, 78, 183, 179, 50, 76, 145, 69, 52, 208, 125, 2, 217, 68, 127, 206, 27, 22, 0, 27, 206, 39, 152, 178, 37, 78, 164, 123, 166, 55, 197, 49, 176, 142, 128, 85, 189, 220, 243, 181, 195, 244}

	for i := 0; i < b.N; i++ {
		header, err := e.DecryptHeader(cipherText, key, nonce)

		if err != nil {
			b.Error(err)
		}
		if !reflect.DeepEqual(*header, testHeader) {
			b.Error("header decryption failed")
		}
	}
}

func TestEncryptMessageBody(t *testing.T) {
	e := NewAES()
	message := &TextMessage{Name: "Test", Body: "Test"}
	key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
	nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
	cipherText, err := e.EncryptMessageBody(message, key, nonce)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(cipherText)
	expectedCipherText := []byte{188, 87, 73, 94, 222, 79, 92, 35, 244, 60, 195, 198, 149, 20, 156, 189, 36, 116, 103, 125, 2, 187, 57, 242, 3, 253, 254, 94, 155, 32, 58, 217, 133, 221, 95, 19, 89, 235, 8, 42, 148, 224, 38, 74, 39, 113, 215, 14, 155, 33, 84, 128, 47, 72, 35, 246, 33, 200, 119, 239, 238, 77, 4, 171, 187, 9, 191, 28, 46, 143, 117, 43, 174, 175, 122, 144}
	if !reflect.DeepEqual(cipherText, expectedCipherText) {
		t.Error("message encryption failed")
	}

}

func BenchmarkEncryptMessageBody(b *testing.B) {
	e := NewAES()
	message := &TextMessage{Body: "Test"}
	key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
	nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
	expectedCipherText := []byte{181, 87, 73, 94, 222, 79, 92, 35, 244, 60, 195, 198, 149, 20, 156, 189, 36, 116, 103, 125, 2, 187, 57, 241, 3, 253, 242, 80, 146, 60, 58, 217, 133, 220, 91, 88, 201, 11, 112, 47, 204, 133, 85, 62, 40, 51, 211, 176, 45, 166, 96, 136, 188, 175, 160, 252, 226, 184, 3, 56, 98}
	for i := 0; i < b.N; i++ {
		cipherText, err := e.EncryptMessageBody(message, key, nonce)

		if err != nil {
			b.Error(err)
		}

		if !reflect.DeepEqual(cipherText, expectedCipherText) {
			b.Error("message encryption failed")
		}

	}
}

func TestDecryptMessageBody(t *testing.T) {
	e := NewAES()
	message := &TextMessage{Body: "Test"}
	key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
	nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
	cipherText := []byte{181, 87, 73, 94, 222, 79, 92, 35, 244, 60, 195, 198, 149, 20, 156, 189, 36, 116, 103, 125, 2, 187, 57, 241, 3, 253, 242, 80, 146, 60, 58, 217, 133, 220, 91, 88, 201, 11, 112, 47, 204, 133, 85, 62, 40, 51, 211, 176, 45, 166, 96, 136, 188, 175, 160, 252, 226, 184, 3, 56, 98}
	plaintext, err := e.DecryptMessageBody(cipherText, key, nonce, 3)
	if err != nil {
		fmt.Println(err)
	}

	if !reflect.DeepEqual(plaintext.(*TextMessage), message) {
		t.Error("message decryption failed")
	}
}

func BenchmarkDecryptMessageBody(b *testing.B) {
	e := NewAES()
	message := &TextMessage{Body: "Test"}
	key := []byte{125, 108, 205, 217, 117, 220, 43, 125, 8, 231, 236, 166, 66, 244, 203, 229, 48, 16, 205, 91, 247, 53, 67, 122, 104, 4, 248, 136, 99, 106, 245, 168}
	nonce := []byte{231, 105, 16, 98, 199, 200, 124, 56, 123, 202, 182, 101}
	cipherText := []byte{181, 87, 73, 94, 222, 79, 92, 35, 244, 60, 195, 198, 149, 20, 156, 189, 36, 116, 103, 125, 2, 187, 57, 241, 3, 253, 242, 80, 146, 60, 58, 217, 133, 220, 91, 88, 201, 11, 112, 47, 204, 133, 85, 62, 40, 51, 211, 176, 45, 166, 96, 136, 188, 175, 160, 252, 226, 184, 3, 56, 98}

	for i := 0; i < b.N; i++ {
		plaintext, err := e.DecryptMessageBody(cipherText, key, nonce, 3)

		if err != nil {
			b.Error(err)
		}

		if !reflect.DeepEqual(plaintext.(*TextMessage), message) {
			b.Error("message decryption failed")
		}

	}
}

package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"io"
)

type ECDH interface {
	GenerateKey(io.Reader) (crypto.PrivateKey, crypto.PublicKey, error)
	Marshal(crypto.PublicKey) []byte
	Unmarshal([]byte) (crypto.PublicKey, bool)
	GenerateSharedSecret(crypto.PrivateKey, crypto.PublicKey) ([]byte, error)
}

type RSA interface {
	GenerateKey(io.Reader) (*rsa.PrivateKey, *rsa.PublicKey, error)
	SignMessage(io.Reader, rsa.PrivateKey, Message) (*Message, error)
	VerifyMessage(io.Reader, rsa.PublicKey, Message) error
}

type Message struct {
	ID        int
	Message   []byte
	Signature []byte
}
type MessageInitial struct {
	ID      int
	Message rsa.PublicKey
}

type AccountInfo struct {
	Hostname         string
	PrivateKey       rsa.PrivateKey
	PublicKey        rsa.PublicKey
	MessageKeys      []MessageKey
	IDIndex          int
	PartnerPublicKey rsa.PublicKey
	PartnerHostname  string
}

type MessageKey struct {
	ID    int
	Key   []byte
	Nonce []byte
}

type MessageKeyInit struct {
	ID         int
	Nonce      []byte
	PublicKey  crypto.PublicKey
	PrivateKey crypto.PrivateKey
}

func init() {
	gob.Register(Message{})
	gob.Register(MessageInitial{})
}

var account AccountInfo

func main() {

	rsaTool := NewRSA()
	privateKey, publicKey, err := rsaTool.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
	}
	hostname := "127.0.0.1:9000"
	var messageKeys []MessageKey
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	_, err = io.ReadFull(rand.Reader, key)
	_, err = io.ReadFull(rand.Reader, nonce)
	initalMessageKey := &MessageKey{
		ID:    0,
		Key:   key,
		Nonce: nonce,
	}
	messageKeys = append(messageKeys, *initalMessageKey)
	key = make([]byte, 32)
	nonce = make([]byte, 12)
	_, err = io.ReadFull(rand.Reader, key)
	_, err = io.ReadFull(rand.Reader, nonce)
	initalMessageKey = &MessageKey{
		ID:    1,
		Key:   key,
		Nonce: nonce,
	}
	messageKeys = append(messageKeys, *initalMessageKey)
	account = AccountInfo{
		Hostname:    hostname,
		PrivateKey:  *privateKey,
		PublicKey:   *publicKey,
		MessageKeys: messageKeys,
		IDIndex:     0,
	}

}

func decryptMessage(message Message, account AccountInfo) (*Message, error) {
	messageKey := account.MessageKeys[message.ID]
	rsaTool := NewRSA()
	err := rsaTool.VerifyMessage(rand.Reader, account.PartnerPublicKey, message)
	if err != nil {
		return nil, err
	}
	decryptedMessage, err := aesDecrypt(message.Message, messageKey.Key, messageKey.Nonce)
	if err != nil {
		return nil, err
	}
	return &Message{ID: message.ID, Message: decryptedMessage, Signature: message.Signature}, nil

}

func encryptMessage(index int, message string, account AccountInfo) (*Message, error) {
	messageKey := account.MessageKeys[index]
	encryptedMessage, err := aesEncrypt([]byte(message), messageKey.Key, messageKey.Nonce)
	if err != nil {
		return nil, err
	}
	rsaTool := NewRSA()
	messageSignature, err := rsaTool.SignMessage(rand.Reader, account.PrivateKey, Message{ID: index, Message: encryptedMessage})
	if err != nil {
		return nil, err
	}
	return messageSignature, nil
}

func aesEncrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)
	return ciphertext, nil
}

func aesDecrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

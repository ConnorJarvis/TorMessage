package main

import (
	"crypto"
	"crypto/rsa"
	"encoding/gob"
	"io"
)

type ECDH interface {
	GenerateKey(io.Reader) (crypto.PrivateKey, crypto.PublicKey, error)
	Marshal(crypto.PublicKey) []byte
	Unmarshal([]byte) (crypto.PublicKey, bool)
	GenerateSharedSecret(crypto.PrivateKey, crypto.PublicKey) ([]byte, error)
}

type RSA interface {
	GenerateRSAKey(io.Reader) (*rsa.PrivateKey, *rsa.PublicKey, error)
	SignMessage(io.Reader, rsa.PrivateKey, MessageEncrypted) (*MessageEncrypted, error)
	VerifyMessage(io.Reader, rsa.PublicKey, MessageEncrypted) error
}
type AES interface {
	Encrypt([]byte, []byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte, []byte) ([]byte, error)
	GenerateAESKey(io.Reader) ([]byte, error)
	GenerateAESNonce(io.Reader) ([]byte, error)
	EncryptHeader(Header, []byte, []byte) ([]byte, error)
	DecryptHeader([]byte, []byte, []byte) (*Header, error)
}

type MessageEncrypted struct {
	ID               int
	HeaderNonce      []byte
	MessageNonce     []byte
	Header           []byte
	Message          []byte
	HeaderSignature  []byte
	MessageSignature []byte
}

type MessageUnencrypted struct {
	ID               int
	Nonce            []byte
	Header           Header
	Message          interface{}
	HeaderSignature  []byte
	MessageSignature []byte
}

type Header struct {
	MessageVersion int
	MessageType    int
	Hostname       string
}

type InitialMessage struct {
	PublicKey    rsa.PublicKey
	DHPublicKeys []MessageKeyInitializers
}

type NegotiateKeysMessage struct {
	DHPublicKeys []MessageKeyInitializers
}

type TextMessage struct {
	Message string
}

type MessageKeyInitializers struct {
	ID         int
	PublicKey  rsa.PublicKey
	PrivateKey rsa.PrivateKey
}

type MessageKey struct {
	ID  int
	Key []byte
}

type ConversationInfo struct {
	Hostname                        string
	PrivateKey                      rsa.PrivateKey
	PublicKey                       rsa.PublicKey
	SendingMessageKeys              []MessageKey
	SendingMessageKeyInitializers   []MessageKeyInitializers
	ReceivingMessageKeys            []MessageKey
	ReceivingMessageKeyInitializers []MessageKeyInitializers
	SendingMessageIndex             int
	RecievingMessageIndex           int
	PartnerPublicKey                rsa.PublicKey
	PartnerHostname                 string
}

func init() {
	gob.Register(MessageEncrypted{})
	gob.Register(Header{})
	gob.Register(InitialMessage{})
	gob.Register(NegotiateKeysMessage{})
	gob.Register(TextMessage{})
}

var conversation ConversationInfo

func main() {

}

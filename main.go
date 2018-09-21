package main

import (
	"crypto"
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
	GenerateRSAKey(io.Reader) (*rsa.PrivateKey, *rsa.PublicKey, error)
}
type AES interface {
	Encrypt([]byte, []byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte, []byte) ([]byte, error)
	GenerateAESKey(io.Reader) ([]byte, error)
	GenerateAESNonce(io.Reader) ([]byte, error)
	EncryptHeader(Header, []byte, []byte) ([]byte, error)
	DecryptHeader([]byte, []byte, []byte) (*Header, error)
	EncryptMessageBody(interface{}, []byte, []byte) ([]byte, error)
	DecryptMessageBody([]byte, []byte, []byte, int) (interface{}, error)
}

type Messages interface {
	EncryptMessage(MessageUnencrypted, MessageKey, rsa.PrivateKey) (*MessageEncrypted, error)
	DecryptMessage(MessageEncrypted, MessageKey) (*MessageUnencrypted, error)
	SignMessage(io.Reader, rsa.PrivateKey, MessageEncrypted) (*MessageEncrypted, error)
	VerifyMessage(io.Reader, rsa.PublicKey, MessageEncrypted) error
}

type Conversation interface {
	CreateKeyInitializers(int) ([]MessageKeyInitializer, error)
	RecieveKeyInitializers([]MessageKeyInitializer) ([]MessageKeyInitializer, error)
	State() ConversationInfo
	RecieveMessage(MessageEncrypted) error
	GetReceiveMessageKey(int) (*MessageKey, error)
	RemoveReceiveMessageKey(int) error
	HandleInitialMessage(InitialMessage) error
	PrepareMessage(MessageUnencrypted) error
	PrepareNegotiateKeysMessage() error
}

type MessageEncrypted struct {
	ID              int
	HeaderNonce     []byte
	BodyNonce       []byte
	Header          []byte
	Body            []byte
	HeaderSignature []byte
	BodySignature   []byte
}

type MessageUnencrypted struct {
	ID              int
	HeaderNonce     []byte
	BodyNonce       []byte
	Header          Header
	Body            interface{}
	HeaderSignature []byte
	BodySignature   []byte
}

type Header struct {
	MessageVersion int
	MessageType    int
	Hostname       string
}

type InitialMessage struct {
	PublicKey    rsa.PublicKey
	DHPublicKeys []MessageKeyInitializer
}

type NegotiateKeysMessage struct {
	HostPublicKeys    []MessageKeyInitializer
	PartnerPublicKeys []MessageKeyInitializer
}

type TextMessage struct {
	Body string
}

type MessageKeyInitializer struct {
	ID         int
	PublicKey  crypto.PublicKey
	PrivateKey crypto.PrivateKey
	Key        []byte
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
	SendingMessageKeyInitializers   []MessageKeyInitializer
	ReceivingMessageKeys            []MessageKey
	ReceivingMessageKeyInitializers []MessageKeyInitializer
	SendingMessageIndex             int
	RecievingMessageIndex           int
	PartnerPublicKey                *rsa.PublicKey
	PartnerHostname                 string
	SendQueue                       chan MessageEncrypted
	RecieveQueue                    chan MessageEncrypted
}

func init() {
	gob.Register(MessageEncrypted{})
	gob.Register(Header{})
	gob.Register(InitialMessage{})
	gob.Register(NegotiateKeysMessage{})
	gob.Register(TextMessage{})
	gob.Register([32]byte{})
}

func main() {
	RSATools := NewRSA()
	AESTools := NewAES()
	privateKey, publicKey, err := RSATools.GenerateRSAKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
	}
	var messageKeys []MessageKey

	for i := 0; i < 3; i++ {
		aesKey, err := AESTools.GenerateAESKey(rand.Reader)
		if err != nil {
			fmt.Println(err)
		}
		messageKeys = append(messageKeys, MessageKey{ID: i, Key: aesKey})

	}

	hostConversationInfo := &ConversationInfo{
		Hostname:              "127.0.0.1:9000",
		PrivateKey:            *privateKey,
		PublicKey:             *publicKey,
		SendingMessageKeys:    []MessageKey{MessageKey{ID: 0, Key: messageKeys[2].Key}},
		ReceivingMessageKeys:  messageKeys[:2],
		SendingMessageIndex:   0,
		RecievingMessageIndex: 0,
		SendQueue:             make(chan MessageEncrypted),
		RecieveQueue:          make(chan MessageEncrypted),
	}
	hostConversation := NewConversation(*hostConversationInfo)
	go SendQueue(hostConversation.State().SendQueue)
	err = hostConversation.PrepareNegotiateKeysMessage()
	if err != nil {
		fmt.Println(err)
	}
	for {

	}
	// privateKey2, publicKey2, err := RSATools.GenerateRSAKey(rand.Reader)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// partnerConversationInfo := &ConversationInfo{
	// 	Hostname:              "127.0.0.1:9001",
	// 	PrivateKey:            *privateKey2,
	// 	PublicKey:             *publicKey2,
	// 	SendingMessageKeys:    messageKeys[:2],
	// 	ReceivingMessageKeys:  []MessageKey{MessageKey{ID: 0, Key: messageKeys[2].Key}},
	// 	SendingMessageIndex:   0,
	// 	RecievingMessageIndex: 0,
	// 	PartnerPublicKey:      publicKey,
	// 	PartnerHostname:       "127.0.0.1:9000",
	// 	SendQueue:             *new(chan MessageEncrypted),
	// 	RecieveQueue:          *new(chan MessageEncrypted),
	// }
	// partnerConversation := NewConversation(*partnerConversationInfo)
}

func SendQueue(send chan MessageEncrypted) {
	for {
		message := <-send
		fmt.Println(message)
	}
}

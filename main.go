package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"io"
	"reflect"
	"time"
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
	CreateSendKeyInitializers(int) ([]MessageKeyInitializer, error)
	CreateReceiveKeyInitializers(int) ([]MessageKeyInitializer, error)
	ComputeKeyMessages([]MessageKeyInitializer, []MessageKeyInitializer) ([]MessageKey, error)
	State() ConversationInfo
	ReceiveMessage(MessageEncrypted) error
	GetSendMessageKey(int) (*MessageKey, error)
	GetReceiveMessageKey(int) (*MessageKey, error)
	GetReceiveMessageKeyInitializer(int) (*MessageKeyInitializer, error)
	RemoveReceiveMessageKey(int) error
	RemoveSendMessageKey(int) error
	HandleNegotiateKeysMessage(*NegotiateKeysMessage) error
	HandleTextMessage(*TextMessage) error
	PrepareMessage(MessageUnencrypted) (*MessageEncrypted, error)
	SendMessage(MessageEncrypted) error
	PrepareNegotiateKeysMessage(*[]MessageKeyInitializer, *[]MessageKeyInitializer) error
	StartConnection(MessageUnencrypted) error
	NegotiateKeys(MessageUnencrypted) error
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
	PublicKey         rsa.PublicKey
	PartnerPublicKeys []MessageKeyInitializer
}

type NegotiateKeysMessage struct {
	HostPublicKeys    *[]MessageKeyInitializer
	PartnerPublicKeys *[]MessageKeyInitializer
}

type TextMessage struct {
	Body string
}

type MessageKeyInitializer struct {
	ID         int
	PublicKey  []byte
	PrivateKey crypto.PrivateKey
	Key        []byte
}

type MessageKey struct {
	ID  int
	Key []byte
}

type ConversationInfo struct {
	Hostname                             string
	PrivateKey                           rsa.PrivateKey
	PublicKey                            rsa.PublicKey
	SendingMessageKeys                   []MessageKey
	SendingMessageKeyInitializers        []MessageKeyInitializer
	ReceivingMessageKeys                 []MessageKey
	ReceivingMessageKeyInitializers      []MessageKeyInitializer
	SendingMessageIndex                  int
	SendingMessageKeyInitializersIndex   int
	ReceivingMessageIndex                int
	ReceivingMessageKeyInitializersIndex int
	PartnerPublicKey                     *rsa.PublicKey
	PartnerHostname                      string
	SendQueue                            chan MessageEncrypted
	RecieveQueue                         chan MessageEncrypted
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
		Hostname:                             "127.0.0.1:9000",
		PrivateKey:                           *privateKey,
		PublicKey:                            *publicKey,
		SendingMessageKeys:                   []MessageKey{MessageKey{ID: 0, Key: messageKeys[2].Key}},
		ReceivingMessageKeys:                 []MessageKey{MessageKey{ID: 0, Key: messageKeys[0].Key}, MessageKey{ID: 1, Key: messageKeys[1].Key}},
		SendingMessageIndex:                  0,
		SendingMessageKeyInitializersIndex:   0,
		ReceivingMessageIndex:                0,
		ReceivingMessageKeyInitializersIndex: 1,
		SendQueue:                            make(chan MessageEncrypted),
		RecieveQueue:                         make(chan MessageEncrypted),
	}
	hostConversation := NewConversation(*hostConversationInfo)

	privateKey2, publicKey2, err := RSATools.GenerateRSAKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
	}
	partnerConversationInfo := &ConversationInfo{
		Hostname:                             "127.0.0.1:9001",
		PrivateKey:                           *privateKey2,
		PublicKey:                            *publicKey2,
		SendingMessageKeys:                   []MessageKey{MessageKey{ID: 0, Key: messageKeys[0].Key}, MessageKey{ID: 1, Key: messageKeys[1].Key}},
		ReceivingMessageKeys:                 []MessageKey{MessageKey{ID: 0, Key: messageKeys[2].Key}},
		SendingMessageIndex:                  0,
		SendingMessageKeyInitializersIndex:   1,
		ReceivingMessageIndex:                0,
		ReceivingMessageKeyInitializersIndex: 0,
		PartnerPublicKey:                     publicKey,
		PartnerHostname:                      "127.0.0.1:9000",
		SendQueue:                            make(chan MessageEncrypted),
		RecieveQueue:                         make(chan MessageEncrypted),
	}

	partnerConversation := NewConversation(*partnerConversationInfo)

	partnerPublicKeys, err := partnerConversation.CreateReceiveKeyInitializers(5)
	if err != nil {
		fmt.Println(err)
	}

	initialMessage := InitialMessage{
		PublicKey:         partnerConversation.State().PublicKey,
		PartnerPublicKeys: partnerPublicKeys,
	}

	header := Header{
		MessageType:    1,
		MessageVersion: 1,
		Hostname:       partnerConversation.State().Hostname,
	}

	unEncryptedMessage := MessageUnencrypted{
		ID:     0,
		Header: header,
		Body:   initialMessage,
	}

	go LinkConvos(partnerConversation.State().SendQueue, hostConversation)

	go LinkConvos(hostConversation.State().SendQueue, partnerConversation)

	time.Sleep(time.Second * 2)
	fmt.Println("Initial Connection and Key Negotation")
	err = partnerConversation.StartConnection(unEncryptedMessage)
	if err != nil {
		fmt.Println(err)

	}
	time.Sleep(time.Second * 5)
	fmt.Println(reflect.DeepEqual(partnerConversation.State().SendingMessageKeys, hostConversation.State().ReceivingMessageKeys))
	fmt.Println(reflect.DeepEqual(partnerConversation.State().ReceivingMessageKeys, hostConversation.State().SendingMessageKeys))

	time.Sleep(time.Second * 5)
	partnerPublicKeys, err = partnerConversation.CreateReceiveKeyInitializers(5)
	if err != nil {
		fmt.Println(err)

	}
	for _, partnerKeyInitalizer := range partnerPublicKeys {
		partnerKeyInitalizer.Key = nil
		partnerKeyInitalizer.PrivateKey = nil
	}
	negotiateMessage := NegotiateKeysMessage{
		PartnerPublicKeys: &partnerPublicKeys,
	}

	header = Header{
		MessageType:    2,
		MessageVersion: 1,
		Hostname:       partnerConversation.State().Hostname,
	}

	unEncryptedMessage = MessageUnencrypted{
		ID:     partnerConversation.State().SendingMessageIndex,
		Header: header,
		Body:   negotiateMessage,
	}
	fmt.Println("Key Negotation")
	err = partnerConversation.NegotiateKeys(unEncryptedMessage)
	if err != nil {
		fmt.Println(err)
	}
	time.Sleep(time.Second * 5)
	fmt.Println(reflect.DeepEqual(partnerConversation.State().SendingMessageKeys, hostConversation.State().ReceivingMessageKeys))
	fmt.Println(reflect.DeepEqual(partnerConversation.State().ReceivingMessageKeys, hostConversation.State().SendingMessageKeys))
	textMessage := TextMessage{
		Body: "Test",
	}

	header = Header{
		MessageType:    3,
		MessageVersion: 1,
		Hostname:       partnerConversation.State().Hostname,
	}

	unEncryptedMessage = MessageUnencrypted{
		ID:     partnerConversation.State().SendingMessageIndex,
		Header: header,
		Body:   textMessage,
	}
	message, err := partnerConversation.PrepareMessage(unEncryptedMessage)
	if err != nil {
		fmt.Println(err)
	}
	err = partnerConversation.SendMessage(*message)
	for {

	}
}

func LinkConvos(queue1 chan MessageEncrypted, conversation Conversation) {
	for {
		message := <-queue1
		err := conversation.ReceiveMessage(message)
		if err != nil {
			fmt.Println(err)
		}
	}
}

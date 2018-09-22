package tormessage

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
	ReceiveMessageProcessor(chan MessageEncrypted)
	StartSendService()
}

type Chat interface {
	InitializeConversation(*string) (*string, error)
	InitiateConnection() error
	NegotiateNewKeys() error
	SendTextMessage(string) error
	State() ChatInformation
	StartServer()
	StartKeyNegotiatingService()
}

type Desktop interface {
	StartApp() error
}

type DesktopInformation struct {
	Platform string
	Chat     Chat
}

type ChatInformation struct {
	Hostname        string
	PartnerHostname string
	Name            string
	Host            bool
	Conversation    Conversation
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
	Name string
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
	SendQueue                            chan MessageUnencrypted
	ReceiveQueue                         chan MessageEncrypted
	DisplayQueue                         chan TextMessage
}

type InitializingData struct {
	Hostname             string
	PublicKey            rsa.PublicKey
	SendingMessageKeys   []MessageKey
	ReceivingMessageKeys []MessageKey
}

func init() {
	gob.Register(MessageEncrypted{})
	gob.Register(Header{})
	gob.Register(InitialMessage{})
	gob.Register(NegotiateKeysMessage{})
	gob.Register(TextMessage{})
	gob.Register(InitializingData{})
	gob.Register([32]byte{})
}

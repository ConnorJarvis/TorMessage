package tormessage

import (
	"crypto"
	"crypto/rsa"
	"encoding/gob"
)

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

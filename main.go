package main

import (
	"bufio"
	"crypto"
	"crypto/rsa"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"os"
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

func main() {
	host := flag.Bool("host", false, "Set if you are the host of the chat")
	hostname := flag.String("hostname", "127.0.0.1:9000", "ip:port to listen on")
	name := flag.String("name", "User", "Display Name")
	extradata := flag.String("extradata", "", "If you are not the host enter the string given to you here")

	flag.Parse()

	chatInfo := ChatInformation{
		Hostname: *hostname,
		Host:     *host,
		Name:     *name,
	}
	var chat Chat
	if *host == true {
		chat = NewChat(chatInfo)
		data, err := chat.InitializeConversation(nil)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(*data)
	} else {
		chat = NewChat(chatInfo)
		data, err := chat.InitializeConversation(extradata)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(data)
	}
	go chat.StartServer()
	go chat.State().Conversation.StartSendService()
	go chat.State().Conversation.ReceiveMessageProcessor(chat.State().Conversation.State().ReceiveQueue)
	if *host == false {
		err := chat.InitiateConnection()
		if err != nil {
			fmt.Println(err)
		}
		time.Sleep(time.Second * 5)
		go chat.StartKeyNegotiatingService()
	}
	go printChat(chat.State().Conversation.State().DisplayQueue)
	listenToInput(chat)
}

func listenToInput(chat Chat) {
	for {
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		chat.SendTextMessage(text)
	}
}

func printChat(messages chan TextMessage) {
	for {
		message := <-messages
		fmt.Print("\n" + message.Name + ": " + message.Body)
	}
}

func printStats(hostChat Chat) {
	for {
		fmt.Print("\n\nHost Chat:\n")
		fmt.Print("Send Keys: ")
		fmt.Print(len(hostChat.State().Conversation.State().SendingMessageKeys))
		fmt.Print("\nReceive Keys: ")
		fmt.Print(len(hostChat.State().Conversation.State().ReceivingMessageKeys))
		fmt.Print("\n\n")
		time.Sleep(time.Second * 5)
	}
}

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/firstrow/tcp_server"
)

type chatTools struct {
	Chat
	ChatState ChatInformation
}

func NewChat(chatInformation ChatInformation) Chat {
	return &chatTools{ChatState: chatInformation}
}

func (e *chatTools) InitializeConversation(initializingData *string) (*string, error) {
	if initializingData == nil {
		RSATools := NewRSA()
		AESTools := NewAES()
		privateKey, publicKey, err := RSATools.GenerateRSAKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		var messageKeys []MessageKey

		for i := 0; i < 3; i++ {
			aesKey, err := AESTools.GenerateAESKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			messageKeys = append(messageKeys, MessageKey{ID: i, Key: aesKey})

		}
		conversationInfo := &ConversationInfo{
			Hostname:                             e.ChatState.Hostname,
			PrivateKey:                           *privateKey,
			PublicKey:                            *publicKey,
			SendingMessageKeys:                   []MessageKey{MessageKey{ID: 0, Key: messageKeys[2].Key}},
			ReceivingMessageKeys:                 []MessageKey{MessageKey{ID: 0, Key: messageKeys[0].Key}, MessageKey{ID: 1, Key: messageKeys[1].Key}},
			SendingMessageIndex:                  0,
			SendingMessageKeyInitializersIndex:   0,
			ReceivingMessageIndex:                0,
			ReceivingMessageKeyInitializersIndex: 1,
			SendQueue:                            make(chan MessageUnencrypted),
			ReceiveQueue:                         make(chan MessageEncrypted),
			DisplayQueue:                         make(chan TextMessage),
		}
		conversation := NewConversation(*conversationInfo)
		e.ChatState.Conversation = conversation
		partnerInitializingData := &InitializingData{
			Hostname:             e.ChatState.Hostname,
			PublicKey:            e.ChatState.Conversation.State().PublicKey,
			SendingMessageKeys:   []MessageKey{MessageKey{ID: 0, Key: messageKeys[0].Key}, MessageKey{ID: 1, Key: messageKeys[1].Key}},
			ReceivingMessageKeys: []MessageKey{MessageKey{ID: 0, Key: messageKeys[2].Key}},
		}
		bytes := bytes.Buffer{}
		encoder := gob.NewEncoder(&bytes)
		err = encoder.Encode(partnerInitializingData)
		encoded := base64.StdEncoding.EncodeToString(bytes.Bytes())
		return &encoded, nil
	} else {
		initializingDataDecoded, err := base64.StdEncoding.DecodeString(*initializingData)
		if err != nil {
			return nil, err
		}
		initalBytes := bytes.Buffer{}
		initalBytes.Write(initializingDataDecoded)
		decoder := gob.NewDecoder(&initalBytes)
		initialData := InitializingData{}
		err = decoder.Decode(&initialData)
		if err != nil {
			return nil, err
		}
		RSATools := NewRSA()

		privateKey, publicKey, err := RSATools.GenerateRSAKey(rand.Reader)

		conversationInfo := &ConversationInfo{
			Hostname:                             e.ChatState.Hostname,
			PrivateKey:                           *privateKey,
			PublicKey:                            *publicKey,
			SendingMessageKeys:                   initialData.SendingMessageKeys,
			ReceivingMessageKeys:                 initialData.ReceivingMessageKeys,
			SendingMessageIndex:                  0,
			SendingMessageKeyInitializersIndex:   1,
			ReceivingMessageIndex:                0,
			ReceivingMessageKeyInitializersIndex: 0,
			PartnerHostname:                      initialData.Hostname,
			PartnerPublicKey:                     &initialData.PublicKey,
			SendQueue:                            make(chan MessageUnencrypted),
			ReceiveQueue:                         make(chan MessageEncrypted),
			DisplayQueue:                         make(chan TextMessage),
		}
		conversation := NewConversation(*conversationInfo)
		e.ChatState.Conversation = conversation
	}
	return nil, nil
}

func (e *chatTools) InitiateConnection() error {
	partnerPublicKeys, err := e.ChatState.Conversation.CreateReceiveKeyInitializers(10)
	if err != nil {
		return err
	}
	for _, partnerKeyInitalizer := range partnerPublicKeys {
		partnerKeyInitalizer.Key = nil
		partnerKeyInitalizer.PrivateKey = nil
	}
	initialMessage := InitialMessage{
		PublicKey:         e.ChatState.Conversation.State().PublicKey,
		PartnerPublicKeys: partnerPublicKeys,
	}

	header := Header{
		MessageType:    1,
		MessageVersion: 1,
		Hostname:       e.ChatState.Conversation.State().Hostname,
	}

	unEncryptedMessage := MessageUnencrypted{
		ID:     e.ChatState.Conversation.State().SendingMessageIndex,
		Header: header,
		Body:   initialMessage,
	}
	err = e.ChatState.Conversation.StartConnection(unEncryptedMessage)
	if err != nil {
		return err
	}
	return nil
}

func (e *chatTools) NegotiateNewKeys() error {

	partnerPublicKeys, err := e.ChatState.Conversation.CreateReceiveKeyInitializers(10)
	if err != nil {
		return err
	}
	for _, partnerKeyInitalizer := range partnerPublicKeys {
		partnerKeyInitalizer.Key = nil
		partnerKeyInitalizer.PrivateKey = nil
	}
	initialMessage := NegotiateKeysMessage{
		PartnerPublicKeys: &partnerPublicKeys,
	}

	header := Header{
		MessageType:    2,
		MessageVersion: 1,
		Hostname:       e.ChatState.Conversation.State().Hostname,
	}

	unEncryptedMessage := MessageUnencrypted{
		ID:     e.ChatState.Conversation.State().SendingMessageIndex,
		Header: header,
		Body:   initialMessage,
	}
	err = e.ChatState.Conversation.NegotiateKeys(unEncryptedMessage)
	if err != nil {
		return err
	}
	return nil
}

func (e *chatTools) SendTextMessage(message string) error {
	textMessage := TextMessage{
		Name: e.ChatState.Name,
		Body: message,
	}

	header := Header{
		MessageType:    3,
		MessageVersion: 1,
		Hostname:       e.ChatState.Hostname,
	}

	unEncryptedMessage := MessageUnencrypted{
		ID:     e.ChatState.Conversation.State().SendingMessageIndex,
		Header: header,
		Body:   textMessage,
	}

	e.ChatState.Conversation.State().SendQueue <- unEncryptedMessage
	return nil
}

func (e *chatTools) State() ChatInformation {
	return e.ChatState
}

func (e *chatTools) StartServer() {
	server := tcp_server.New(e.ChatState.Hostname)
	server.OnNewMessage(func(c *tcp_server.Client, message string) {
		messageDataDecoded, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			fmt.Println(err)
		}
		initalBytes := bytes.Buffer{}
		initalBytes.Write(messageDataDecoded)
		decoder := gob.NewDecoder(&initalBytes)
		initialData := MessageEncrypted{}
		err = decoder.Decode(&initialData)
		if err != nil {
			fmt.Println(err)
		}
		err = e.ChatState.Conversation.ReceiveMessage(initialData)
		if err != nil {
			fmt.Println(err)
		}
	})

	server.Listen()
}

func (e *chatTools) StartKeyNegotiatingService() {
	for {
		currentSendKeys := len(e.ChatState.Conversation.State().SendingMessageKeys)
		currentReceiveKeys := len(e.ChatState.Conversation.State().ReceivingMessageKeys)
		if currentSendKeys < 25 || currentReceiveKeys < 25 {
			err := e.NegotiateNewKeys()
			if err != nil {
				fmt.Println(err)
			}
		}
		time.Sleep(time.Second * 5)
	}
}

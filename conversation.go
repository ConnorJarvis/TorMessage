package main

import (
	"crypto/rand"
	"errors"
)

type conversationTools struct {
	Conversation
	ConversationState ConversationInfo
}

func NewConversation(info ConversationInfo) Conversation {
	return &conversationTools{ConversationState: info}
}

func (e *conversationTools) RecieveKeyInitializers(initalizers []MessageKeyInitializer) ([]MessageKeyInitializer, error) {
	var computedMessageKeyInitializers []MessageKeyInitializer
	Curve25519ECDH := NewCurve25519ECDH()
	for _, messageKeyInitializer := range initalizers {
		privateKey, publicKey, err := Curve25519ECDH.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		sharedSecret, err := Curve25519ECDH.GenerateSharedSecret(privateKey, messageKeyInitializer.PublicKey)
		if err != nil {
			return nil, err
		}
		computedMessageKeyInitializer := &MessageKeyInitializer{
			ID:        messageKeyInitializer.ID,
			PublicKey: publicKey,
			Key:       sharedSecret,
		}
		computedMessageKeyInitializers = append(computedMessageKeyInitializers, *computedMessageKeyInitializer)
	}
	return computedMessageKeyInitializers, nil
}

func (e *conversationTools) State() ConversationInfo {
	return e.ConversationState
}

func (e *conversationTools) ReceiveMessage(encryptedMessage MessageEncrypted) error {
	AESTools := NewAES()
	if e.ConversationState.PartnerPublicKey == nil {
		messageKey, err := e.GetReceiveMessageKey(encryptedMessage.ID)
		if err != nil {
			return err
		}
		messageHeader, err := AESTools.DecryptHeader(encryptedMessage.Header, messageKey.Key, encryptedMessage.HeaderNonce)
		if err != nil {
			return err
		}
		if messageHeader.MessageType == 1 {
			e.ConversationState.PartnerHostname = messageHeader.Hostname
			messageBody, err := AESTools.DecryptMessageBody(encryptedMessage.Body, messageKey.Key, encryptedMessage.BodyNonce, 1)
			if err != nil {
				return err
			}
			go e.HandleInitialMessage(messageBody.(InitialMessage))
			return nil
		}
		return errors.New("invalid first message")
	}

	err := e.RemoveReceiveMessageKey(encryptedMessage.ID)
	if err != nil {
		return err
	}
	return nil
}

func (e *conversationTools) GetReceiveMessageKey(id int) (*MessageKey, error) {
	for _, messageKey := range e.ConversationState.ReceivingMessageKeys {
		if messageKey.ID == id {
			return &messageKey, nil
		}
	}
	return nil, errors.New("no key")
}

func (e *conversationTools) RemoveReceiveMessageKey(id int) error {
	for index, messageKey := range e.ConversationState.ReceivingMessageKeys {
		if messageKey.ID == id {
			e.ConversationState.ReceivingMessageKeys = append(e.ConversationState.ReceivingMessageKeys[:index], e.ConversationState.ReceivingMessageKeys[index+1:]...)
			return nil
		}
	}
	return errors.New("no key")
}

func (e *conversationTools) HandleInitialMessage(initialMessage InitialMessage) error {
	e.ConversationState.PartnerPublicKey = &initialMessage.PublicKey

	messageKeyInitalizers, err := e.RecieveKeyInitializers(initialMessage.DHPublicKeys)
	if err != nil {
		return err
	}
	for _, messageKeyInitalizer := range messageKeyInitalizers {
		e.ConversationState.ReceivingMessageKeyInitializers = append(e.ConversationState.ReceivingMessageKeyInitializers, messageKeyInitalizer)
		messageKeyInitalizer.Key = nil
	}
	err = e.PrepareNegotiateKeysMessage()
	if err != nil {
		return err
	}
	return nil
}

func (e *conversationTools) CreateKeyInitializers(number int) ([]MessageKeyInitializer, error) {

	var keyInitializers []MessageKeyInitializer
	Curve25519ECDH := NewCurve25519ECDH()
	for i := 1; i <= number; i++ {
		privateKey, publicKey, err := Curve25519ECDH.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		keyInitializer := MessageKeyInitializer{
			ID:         e.ConversationState.SendingMessageIndex + i,
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}
		keyInitializers = append(keyInitializers, keyInitializer)
	}
	for _, keyInitializer := range keyInitializers {
		e.ConversationState.SendingMessageKeyInitializers = append(e.ConversationState.SendingMessageKeyInitializers, keyInitializer)
	}
	return keyInitializers, nil
}

func (e *conversationTools) PrepareNegotiateKeysMessage() error {

	hostKeyInitializers, err := e.CreateKeyInitializers(5)
	if err != nil {
		return err
	}
	NegotiateKeysMessage := NegotiateKeysMessage{
		HostPublicKeys: hostKeyInitializers,
	}
	header := Header{
		MessageType:    2,
		MessageVersion: 1,
		Hostname:       e.ConversationState.Hostname,
	}
	unEncryptedMessage := MessageUnencrypted{
		ID:     e.ConversationState.SendingMessageIndex,
		Header: header,
		Body:   NegotiateKeysMessage,
	}
	err = e.PrepareMessage(unEncryptedMessage)
	if err != nil {
		return err
	}
	return nil

}

func (e *conversationTools) PrepareMessage(unEncryptedMessage MessageUnencrypted) error {
	MessageTools := NewMessages()
	messageKey, err := e.GetReceiveMessageKey(unEncryptedMessage.ID)
	if err != nil {
		return err
	}
	encryptedMessage, err := MessageTools.EncryptMessage(unEncryptedMessage, *messageKey, e.ConversationState.PrivateKey)
	if err != nil {
		return err
	}
	err = e.RemoveReceiveMessageKey(unEncryptedMessage.ID)
	if err != nil {
		return err
	}
	e.ConversationState.SendQueue <- *encryptedMessage
	return nil
}

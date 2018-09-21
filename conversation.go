package main

import (
	"crypto/rand"
	"errors"
	"fmt"
)

type conversationTools struct {
	Conversation
	ConversationState ConversationInfo
}

func NewConversation(info ConversationInfo) Conversation {
	return &conversationTools{ConversationState: info}
}

func (e *conversationTools) ComputeKeyMessages(publicKeys []MessageKeyInitializer, privateKeys []MessageKeyInitializer) ([]MessageKey, error) {
	var computedMessageKeys []MessageKey
	Curve25519ECDH := NewCurve25519ECDH()
	for index, publicKeyInitializer := range publicKeys {

		sharedSecret, err := Curve25519ECDH.GenerateSharedSecret(privateKeys[index].PrivateKey, &publicKeys[index].PublicKey)
		if err != nil {
			return nil, err
		}
		computedMessageKey := &MessageKey{
			ID:  publicKeyInitializer.ID,
			Key: sharedSecret,
		}
		computedMessageKeys = append(computedMessageKeys, *computedMessageKey)
	}
	return computedMessageKeys, nil
}

func (e *conversationTools) State() ConversationInfo {
	return e.ConversationState
}

func (e *conversationTools) ReceiveMessage(encryptedMessage MessageEncrypted) error {
	fmt.Println("test")
	AESTools := NewAES()
	MessageTools := NewMessages()
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
			fmt.Println(messageHeader.Hostname)
			messageBody, err := AESTools.DecryptMessageBody(encryptedMessage.Body, messageKey.Key, encryptedMessage.BodyNonce, 1)
			if err != nil {
				return err
			}
			initialMessage := messageBody.(*InitialMessage)
			e.ConversationState.PartnerPublicKey = &initialMessage.PublicKey

			go e.HandleNegotiateKeyMessage(NegotiateKeysMessage{PartnerPublicKeys: &initialMessage.PartnerPublicKeys})
			return nil
		}

	} else {
		err := MessageTools.VerifyMessage(rand.Reader, *e.ConversationState.PartnerPublicKey, encryptedMessage)
		if err != nil {
			return err
		}
		messageKey, err := e.GetReceiveMessageKey(encryptedMessage.ID)
		if err != nil {
			return err
		}
		messageHeader, err := AESTools.DecryptHeader(encryptedMessage.Header, messageKey.Key, encryptedMessage.HeaderNonce)
		if err != nil {
			return err
		}
		if messageHeader.MessageType == 2 {
			messageBody, err := AESTools.DecryptMessageBody(encryptedMessage.Body, messageKey.Key, encryptedMessage.BodyNonce, 2)
			if err != nil {
				return err
			}
			go e.HandleNegotiateKeyMessage(messageBody.(NegotiateKeysMessage))
		}
	}

	err := e.RemoveReceiveMessageKey(encryptedMessage.ID)
	if err != nil {
		return err
	}
	e.ConversationState.RecievingMessageIndex++
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

func (e *conversationTools) GetSendMessageKey(id int) (*MessageKey, error) {
	for _, messageKey := range e.ConversationState.SendingMessageKeys {
		if messageKey.ID == id {
			return &messageKey, nil
		}
	}
	return nil, errors.New("no key")
}
func (e *conversationTools) RemoveSendMessageKey(id int) error {
	for index, messageKey := range e.ConversationState.SendingMessageKeys {
		if messageKey.ID == id {
			e.ConversationState.SendingMessageKeys = append(e.ConversationState.SendingMessageKeys[:index], e.ConversationState.SendingMessageKeys[index+1:]...)
			return nil
		}
	}
	return errors.New("no key")
}

func (e *conversationTools) GetReceiveMessageKeyInitializer(id int) (*MessageKeyInitializer, error) {
	for _, messageKeyInitializer := range e.ConversationState.ReceivingMessageKeyInitializers {
		if messageKeyInitializer.ID == id {
			return &messageKeyInitializer, nil
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

func (e *conversationTools) HandleNegotiateKeyMessage(negotiateKeyMessage NegotiateKeysMessage) error {
	if negotiateKeyMessage.HostPublicKeys == nil {
		hostKeyInitializers, err := e.CreateKeyInitializers(5)
		if err != nil {
			return err
		}
		partnerKeyInitializers, err := e.CreateKeyInitializers(5)
		if err != nil {
			return err
		}
		messageKeys, err := e.ComputeKeyMessages(*negotiateKeyMessage.PartnerPublicKeys, partnerKeyInitializers)
		if err != nil {
			return err
		}
		for _, messageKey := range messageKeys {
			e.ConversationState.SendingMessageKeys = append(e.ConversationState.SendingMessageKeys, messageKey)
		}
		for _, hostKeyInitalizer := range hostKeyInitializers {
			e.ConversationState.ReceivingMessageKeyInitializers = append(e.ConversationState.ReceivingMessageKeyInitializers, hostKeyInitalizer)
			hostKeyInitalizer.Key = nil
		}

		err = e.PrepareNegotiateKeysMessage(&partnerKeyInitializers, &hostKeyInitializers)
		if err != nil {
			return err
		}
	} else if negotiateKeyMessage.PartnerPublicKeys == nil {
		var hostKeyInitializers []MessageKeyInitializer
		for _, hostKeyInitializer := range *negotiateKeyMessage.HostPublicKeys {
			initalizer, err := e.GetReceiveMessageKeyInitializer(hostKeyInitializer.ID)
			if err != nil {
				return err
			}
			hostKeyInitializers = append(hostKeyInitializers, *initalizer)
		}
		messageKeys, err := e.ComputeKeyMessages(*negotiateKeyMessage.HostPublicKeys, hostKeyInitializers)
		if err != nil {
			return err
		}
		for _, messageKey := range messageKeys {
			e.ConversationState.SendingMessageKeys = append(e.ConversationState.ReceivingMessageKeys, messageKey)
		}
		return nil
	} else {
		var partnerKeyInitializers []MessageKeyInitializer
		for _, partnerKeyInitializer := range *negotiateKeyMessage.PartnerPublicKeys {
			initalizer, err := e.GetReceiveMessageKeyInitializer(partnerKeyInitializer.ID)
			if err != nil {
				return err
			}
			partnerKeyInitializers = append(partnerKeyInitializers, *initalizer)
		}
		messageKeys, err := e.ComputeKeyMessages(*negotiateKeyMessage.PartnerPublicKeys, partnerKeyInitializers)
		if err != nil {
			return err
		}
		for _, messageKey := range messageKeys {
			e.ConversationState.SendingMessageKeys = append(e.ConversationState.ReceivingMessageKeys, messageKey)
		}

		hostKeyInitializers, err := e.CreateKeyInitializers(5)
		if err != nil {
			return err
		}

		messageKeys, err = e.ComputeKeyMessages(*negotiateKeyMessage.HostPublicKeys, hostKeyInitializers)
		if err != nil {
			return err
		}
		for _, messageKey := range messageKeys {
			e.ConversationState.SendingMessageKeys = append(e.ConversationState.SendingMessageKeys, messageKey)
		}

		err = e.PrepareNegotiateKeysMessage(nil, &hostKeyInitializers)
		if err != nil {
			return err
		}
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

func (e *conversationTools) PrepareNegotiateKeysMessage(partnerPublicKeys *[]MessageKeyInitializer, hostPublicKeys *[]MessageKeyInitializer) error {

	NegotiateKeysMessage := NegotiateKeysMessage{}
	if partnerPublicKeys != nil {
		NegotiateKeysMessage.PartnerPublicKeys = partnerPublicKeys
	}
	if hostPublicKeys != nil {
		NegotiateKeysMessage.HostPublicKeys = hostPublicKeys
	}
	header := Header{
		MessageType:    2,
		MessageVersion: 1,
		Hostname:       e.ConversationState.Hostname,
	}
	unEncryptedMessage := MessageUnencrypted{
		ID:     e.ConversationState.SendingMessageIndex,
		Header: header,
		Body:   &NegotiateKeysMessage,
	}
	err := e.PrepareMessage(unEncryptedMessage)
	if err != nil {
		return err
	}
	return nil

}

func (e *conversationTools) PrepareMessage(unEncryptedMessage MessageUnencrypted) error {
	MessageTools := NewMessages()
	messageKey, err := e.GetSendMessageKey(unEncryptedMessage.ID)
	if err != nil {
		return err
	}
	encryptedMessage, err := MessageTools.EncryptMessage(unEncryptedMessage, *messageKey, e.ConversationState.PrivateKey)
	if err != nil {
		return err
	}
	err = e.RemoveSendMessageKey(unEncryptedMessage.ID)
	if err != nil {
		return err
	}
	e.ConversationState.SendingMessageIndex++
	e.ConversationState.SendQueue <- *encryptedMessage

	return nil
}

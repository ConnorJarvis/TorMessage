package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"time"
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
		publicKey, isKey := Curve25519ECDH.Unmarshal(publicKeys[index].PublicKey)
		if isKey != true {
			return nil, errors.New("not a public key")
		}
		sharedSecret, err := Curve25519ECDH.GenerateSharedSecret(privateKeys[index].PrivateKey, publicKey)
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

			messageBody, err := AESTools.DecryptMessageBody(encryptedMessage.Body, messageKey.Key, encryptedMessage.BodyNonce, 1)
			if err != nil {
				return err
			}
			initialMessage := messageBody.(*InitialMessage)
			e.ConversationState.PartnerPublicKey = &initialMessage.PublicKey
			err = e.HandleNegotiateKeyMessage(&NegotiateKeysMessage{PartnerPublicKeys: &initialMessage.PartnerPublicKeys})
			if err != nil {
				return err
			}
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

			err = e.HandleNegotiateKeyMessage(messageBody.(*NegotiateKeysMessage))
			if err != nil {
				return err
			}
		} else if messageHeader.MessageType == 3 {
			messageBody, err := AESTools.DecryptMessageBody(encryptedMessage.Body, messageKey.Key, encryptedMessage.BodyNonce, 3)
			if err != nil {
				return err
			}
			err = e.HandleTextMessage(messageBody.(*TextMessage))
			if err != nil {
				return err
			}
		}
	}

	err := e.RemoveReceiveMessageKey(encryptedMessage.ID)
	if err != nil {
		return err
	}
	e.ConversationState.ReceivingMessageIndex++
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

func (e *conversationTools) HandleTextMessage(textMessage *TextMessage) error {
	e.ConversationState.DisplayQueue <- *textMessage
	return nil
}

func (e *conversationTools) HandleNegotiateKeyMessage(negotiateKeyMessage *NegotiateKeysMessage) error {
	if negotiateKeyMessage.HostPublicKeys == nil {
		hostKeyInitializers, err := e.CreateReceiveKeyInitializers(10)
		if err != nil {
			return err
		}
		partnerKeyInitializers, err := e.CreateSendKeyInitializers(10)
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
			hostKeyInitalizer.Key = nil
			hostKeyInitalizer.PrivateKey = nil
		}
		for _, partnerKeyInitalizer := range partnerKeyInitializers {
			partnerKeyInitalizer.Key = nil
			partnerKeyInitalizer.PrivateKey = nil
		}
		err = e.PrepareNegotiateKeysMessage(&partnerKeyInitializers, &hostKeyInitializers)
		if err != nil {
			return err
		}
	} else if negotiateKeyMessage.PartnerPublicKeys == nil {
		var partnerKeyInitializers []MessageKeyInitializer
		for _, partnerKeyInitializer := range *negotiateKeyMessage.HostPublicKeys {
			initalizer, err := e.GetReceiveMessageKeyInitializer(partnerKeyInitializer.ID)
			if err != nil {
				return err
			}
			partnerKeyInitializers = append(partnerKeyInitializers, *initalizer)
		}
		messageKeys, err := e.ComputeKeyMessages(*negotiateKeyMessage.HostPublicKeys, partnerKeyInitializers)
		if err != nil {
			return err
		}
		for _, messageKey := range messageKeys {
			e.ConversationState.ReceivingMessageKeys = append(e.ConversationState.ReceivingMessageKeys, messageKey)
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
			e.ConversationState.ReceivingMessageKeys = append(e.ConversationState.ReceivingMessageKeys, messageKey)
		}

		hostKeyInitializers, err := e.CreateSendKeyInitializers(10)
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
		for _, hostKeyInitalizer := range hostKeyInitializers {
			hostKeyInitalizer.Key = nil
			hostKeyInitalizer.PrivateKey = nil
		}
		err = e.PrepareNegotiateKeysMessage(nil, &hostKeyInitializers)
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *conversationTools) CreateSendKeyInitializers(number int) ([]MessageKeyInitializer, error) {

	var keyInitializers []MessageKeyInitializer
	Curve25519ECDH := NewCurve25519ECDH()
	for i := 1; i <= number; i++ {
		privateKey, publicKey, err := Curve25519ECDH.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		e.ConversationState.SendingMessageKeyInitializersIndex++
		keyInitializer := MessageKeyInitializer{
			ID:         e.ConversationState.SendingMessageKeyInitializersIndex,
			PrivateKey: privateKey,
			PublicKey:  Curve25519ECDH.Marshal(publicKey),
		}

		keyInitializers = append(keyInitializers, keyInitializer)
	}
	for _, keyInitializer := range keyInitializers {
		e.ConversationState.SendingMessageKeyInitializers = append(e.ConversationState.SendingMessageKeyInitializers, keyInitializer)
	}
	return keyInitializers, nil
}

func (e *conversationTools) CreateReceiveKeyInitializers(number int) ([]MessageKeyInitializer, error) {

	var keyInitializers []MessageKeyInitializer
	Curve25519ECDH := NewCurve25519ECDH()
	for i := 1; i <= number; i++ {
		privateKey, publicKey, err := Curve25519ECDH.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		e.ConversationState.ReceivingMessageKeyInitializersIndex++
		keyInitializer := MessageKeyInitializer{
			ID:         e.ConversationState.ReceivingMessageKeyInitializersIndex,
			PrivateKey: privateKey,
			PublicKey:  Curve25519ECDH.Marshal(publicKey),
		}

		keyInitializers = append(keyInitializers, keyInitializer)
	}
	for _, keyInitializer := range keyInitializers {
		e.ConversationState.ReceivingMessageKeyInitializers = append(e.ConversationState.ReceivingMessageKeyInitializers, keyInitializer)
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
	e.ConversationState.SendQueue <- unEncryptedMessage
	return nil

}

func (e *conversationTools) PrepareMessage(unEncryptedMessage MessageUnencrypted) (*MessageEncrypted, error) {
	MessageTools := NewMessages()
	messageKey, err := e.GetSendMessageKey(unEncryptedMessage.ID)
	if err != nil {
		return nil, err
	}
	encryptedMessage, err := MessageTools.EncryptMessage(unEncryptedMessage, *messageKey, e.ConversationState.PrivateKey)
	if err != nil {
		return nil, err
	}
	err = e.RemoveSendMessageKey(unEncryptedMessage.ID)
	if err != nil {
		return nil, err
	}

	return encryptedMessage, nil
}

func (e *conversationTools) StartConnection(unEncryptedMessage MessageUnencrypted) error {

	body := unEncryptedMessage.Body.(InitialMessage)
	for _, init := range body.PartnerPublicKeys {
		e.ConversationState.ReceivingMessageKeyInitializers = append(e.ConversationState.ReceivingMessageKeyInitializers, init)
	}
	e.ConversationState.SendQueue <- unEncryptedMessage

	return nil
}

func (e *conversationTools) NegotiateKeys(unEncryptedMessage MessageUnencrypted) error {

	body := unEncryptedMessage.Body.(NegotiateKeysMessage)
	for _, init := range *body.PartnerPublicKeys {
		e.ConversationState.ReceivingMessageKeyInitializers = append(e.ConversationState.ReceivingMessageKeyInitializers, init)
	}
	e.ConversationState.SendQueue <- unEncryptedMessage

	return nil
}

func (e *conversationTools) ReceiveMessageProcessor(receiveChannel chan MessageEncrypted) {
	for {
		message := <-receiveChannel
		e.ReceiveMessage(message)
	}
}

func (e *conversationTools) StartSendService() {
	for {
		message := <-e.ConversationState.SendQueue
		if (len(e.ConversationState.SendingMessageKeys) < 5 || len(e.ConversationState.ReceivingMessageKeys) < 5) && message.Header.MessageType == 3 {
			go func() {
				time.Sleep(time.Millisecond * 100)
				e.ConversationState.SendQueue <- message
			}()
		} else {
			if e.ConversationState.SendingMessageIndex != message.ID {
				fmt.Println("Changed ID")
			}
			message.ID = e.ConversationState.SendingMessageIndex
			encryptedMessage, err := e.PrepareMessage(message)
			if err != nil {
				fmt.Println(err)
			}
			e.ConversationState.SendingMessageIndex++
			bytes := bytes.Buffer{}
			encoder := gob.NewEncoder(&bytes)
			err = encoder.Encode(encryptedMessage)
			if err != nil {
				fmt.Println(err)
			}
			encoded := base64.StdEncoding.EncodeToString(bytes.Bytes())
			conn, err := net.Dial("tcp", e.ConversationState.PartnerHostname)
			defer conn.Close()

			if err != nil {
				fmt.Println(err)
			}

			conn.Write([]byte(encoded))
			conn.Write([]byte("\n"))
			conn.Close()
		}

	}
}

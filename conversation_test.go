package tormessage

import (
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
)

var hostConversationInfo ConversationInfo
var partnerConversationInfo ConversationInfo

func init() {
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
	hostConversationInfo = ConversationInfo{
		Hostname:                             "127.0.0.1:9000",
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
	}

	privateKey2, publicKey2, err := RSATools.GenerateRSAKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
	}
	partnerConversationInfo = ConversationInfo{
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
		SendQueue:                            make(chan MessageUnencrypted),
		ReceiveQueue:                         make(chan MessageEncrypted),
	}

}
func TestComputeKeyMessages(t *testing.T) {

	hostConversation := NewConversation(hostConversationInfo)
	partnerConversation := NewConversation(partnerConversationInfo)
	receiveKeyInitalizers, err := hostConversation.CreateReceiveKeyInitializers(5)
	if err != nil {
		t.Error(err)
	}
	sendKeyInitalizers, err := partnerConversation.CreateSendKeyInitializers(5)
	if err != nil {
		t.Error(err)
	}
	hostKeys, err := hostConversation.ComputeKeyMessages(sendKeyInitalizers, receiveKeyInitalizers)
	if err != nil {
		t.Error(err)
	}
	partnerKeys, err := partnerConversation.ComputeKeyMessages(receiveKeyInitalizers, sendKeyInitalizers)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(hostKeys, partnerKeys) {
		t.Error(err)
	}

}

func TestState(t *testing.T) {
	hostConversation := NewConversation(hostConversationInfo)
	if !reflect.DeepEqual(hostConversationInfo, hostConversation.State()) {
		t.Error("state doesnt match")
	}
}

func TestReceiveMessage(t *testing.T) {
	hostConversation := NewConversation(hostConversationInfo)
	partnerConversation := NewConversation(partnerConversationInfo)

	textMessage := TextMessage{
		Body: "Test",
	}

	header := Header{
		MessageType:    3,
		MessageVersion: 1,
		Hostname:       partnerConversation.State().Hostname,
	}

	unEncryptedMessage := MessageUnencrypted{
		ID:     partnerConversation.State().SendingMessageIndex,
		Header: header,
		Body:   textMessage,
	}
	message, err := partnerConversation.PrepareMessage(unEncryptedMessage)
	if err != nil {
		t.Error(err)
	}
	err = hostConversation.ReceiveMessage(*message)
	if err != nil {
		t.Error(err)
	}
}

func TestGetReceiveMessageKey(t *testing.T) {
	partnerConversation := NewConversation(partnerConversationInfo)

	key, err := partnerConversation.GetReceiveMessageKey(0)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(*key, partnerConversation.State().ReceivingMessageKeys[0]) {
		t.Error("keys do not match")
	}
}

func TestGetSendMessageKey(t *testing.T) {
	hostConversation := NewConversation(hostConversationInfo)
	key, err := hostConversation.GetSendMessageKey(0)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(*key, hostConversation.State().SendingMessageKeys[0]) {
		t.Error("keys do not match")
	}
}

func TestRemoveSendMessageKey(t *testing.T) {
	hostConversation := NewConversation(hostConversationInfo)
	initialLength := len(hostConversation.State().SendingMessageKeys)
	err := hostConversation.RemoveSendMessageKey(0)
	if err != nil {
		t.Error(err)
	}

	if initialLength == len(hostConversation.State().SendingMessageKeys) {
		t.Error("failed to remove key")
	}
}

func TestRemoveReceiveMessageKey(t *testing.T) {
	partnerConversation := NewConversation(partnerConversationInfo)
	initialLength := len(partnerConversation.State().ReceivingMessageKeys)
	err := partnerConversation.RemoveReceiveMessageKey(0)
	if err != nil {
		t.Error(err)
	}

	if initialLength == len(partnerConversation.State().ReceivingMessageKeys) {
		t.Error("failed to remove key")
	}
}

func TestGetReceiveMessageKeyInitializer(t *testing.T) {
	hostConversation := NewConversation(hostConversationInfo)
	_, err := hostConversation.CreateReceiveKeyInitializers(1)
	if err != nil {
		t.Error(err)
	}
	receiveKeyInitalizer, err := hostConversation.GetReceiveMessageKeyInitializer(2)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(*receiveKeyInitalizer, hostConversation.State().ReceivingMessageKeyInitializers[0]) {
		t.Error("failed to get receive key initalizer")
	}

}

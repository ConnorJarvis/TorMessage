package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

type messageTools struct {
	Messages
}

func NewMessages() Messages {
	return &messageTools{}
}

func (e *messageTools) EncryptMessage(unEncryptedMessage MessageUnencrypted, messageKey MessageKey, privateKey rsa.PrivateKey) (*MessageEncrypted, error) {
	AESTools := NewAES()

	var messageEncrypted MessageEncrypted
	messageEncrypted.ID = unEncryptedMessage.ID

	aesKey := messageKey.Key
	headerNonce, err := AESTools.GenerateAESNonce(rand.Reader)
	if err != nil {
		return nil, err
	}
	encryptedHeader, err := AESTools.EncryptHeader(unEncryptedMessage.Header, aesKey, headerNonce)
	if err != nil {
		return nil, err
	}
	messageEncrypted.Header = encryptedHeader
	messageEncrypted.HeaderNonce = headerNonce

	messageNonce, err := AESTools.GenerateAESNonce(rand.Reader)
	if err != nil {
		return nil, err
	}
	encryptedMessage, err := AESTools.EncryptMessageBody(unEncryptedMessage.Body, aesKey, messageNonce)
	if err != nil {
		return nil, err
	}
	messageEncrypted.Body = encryptedMessage
	messageEncrypted.MessageNonce = messageNonce

	signedMessageEncrypted, err := e.SignMessage(rand.Reader, privateKey, messageEncrypted)
	if err != nil {
		return nil, err
	}
	return signedMessageEncrypted, nil

}

func (e *messageTools) DecryptMessage(encryptedMessage MessageEncrypted, messageKey MessageKey) (*MessageUnencrypted, error) {
	AESTools := NewAES()
	var decryptedMessage MessageUnencrypted
	decryptedMessage.ID = encryptedMessage.ID
	decryptedMessageHeader, err := AESTools.DecryptHeader(encryptedMessage.Header, messageKey.Key, encryptedMessage.HeaderNonce)
	if err != nil {
		return nil, err
	}
	decryptedMessage.Header = *decryptedMessageHeader
	decryptedMessage.HeaderNonce = encryptedMessage.HeaderNonce
	decryptedMessage.HeaderSignature = encryptedMessage.HeaderSignature

	decryptedMessageBody, err := AESTools.DecryptMessageBody(encryptedMessage.Body, messageKey.Key, encryptedMessage.MessageNonce, decryptedMessageHeader.MessageType)
	if err != nil {
		return nil, err
	}
	decryptedMessage.Body = decryptedMessageBody
	decryptedMessage.MessageNonce = encryptedMessage.MessageNonce
	decryptedMessage.MessageSignature = encryptedMessage.MessageSignature

	return &decryptedMessage, nil
}
func (e *messageTools) SignMessage(rand io.Reader, privateKey rsa.PrivateKey, message MessageEncrypted) (*MessageEncrypted, error) {
	messageHasher := sha256.New()
	messageHasher.Write(message.Body)
	messageHash := messageHasher.Sum(nil)

	headerHasher := sha256.New()
	headerHasher.Write(message.Header)
	headerHash := headerHasher.Sum(nil)

	messageSignature, err := rsa.SignPKCS1v15(rand, &privateKey, crypto.SHA256, messageHash)
	if err != nil {
		return nil, err
	}

	headerSignature, err := rsa.SignPKCS1v15(rand, &privateKey, crypto.SHA256, headerHash)
	if err != nil {
		return nil, err
	}

	message.MessageSignature = messageSignature
	message.HeaderSignature = headerSignature
	return &message, nil
}

func (e *messageTools) VerifyMessage(rand io.Reader, publicKey rsa.PublicKey, message MessageEncrypted) error {
	headerHasher := sha256.New()
	headerHasher.Write(message.Header)
	headerHash := headerHasher.Sum(nil)

	err := rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, headerHash, message.HeaderSignature)
	if err != nil {
		return err
	}

	messageHasher := sha256.New()
	messageHasher.Write(message.Body)
	messageHash := messageHasher.Sum(nil)

	err = rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, messageHash, message.MessageSignature)
	if err != nil {
		return err
	}

	return nil
}

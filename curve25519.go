package tormessage

import (
	"crypto"
	"io"

	"golang.org/x/crypto/curve25519"
)

type ECDH interface {
	GenerateKey(io.Reader) (crypto.PrivateKey, crypto.PublicKey, error)
	Marshal(crypto.PublicKey) []byte
	Unmarshal([]byte) (crypto.PublicKey, bool)
	GenerateSharedSecret(crypto.PrivateKey, crypto.PublicKey) ([]byte, error)
}

type curve25519ECDH struct {
	ECDH
}

func NewCurve25519ECDH() ECDH {
	return &curve25519ECDH{}
}

func (e *curve25519ECDH) Marshal(p crypto.PublicKey) []byte {
	pub := p.(*[32]byte)
	return pub[:]
}

func (e *curve25519ECDH) Unmarshal(data []byte) (crypto.PublicKey, bool) {
	var pub [32]byte
	if len(data) != 32 {
		return nil, false
	}

	copy(pub[:], data)
	return &pub, true
}

func (e *curve25519ECDH) GenerateKey(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	var pub, priv [32]byte
	_, err := io.ReadFull(rand, priv[:])
	if err != nil {
		return nil, nil, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)
	return &priv, &pub, nil
}

func (e *curve25519ECDH) GenerateSharedSecret(privKey crypto.PrivateKey, pubKey crypto.PublicKey) ([]byte, error) {
	var priv, pub, secret *[32]byte

	priv = privKey.(*[32]byte)
	pub = pubKey.(*[32]byte)
	secret = new([32]byte)

	curve25519.ScalarMult(secret, priv, pub)
	return secret[:], nil
}

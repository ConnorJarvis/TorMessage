package tormessage

import (
	"crypto/rand"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	e := NewRSA()
	_, _, err := e.GenerateRSAKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e := NewRSA()
		_, _, err := e.GenerateRSAKey(rand.Reader)
		if err != nil {
			b.Error(err)
		}
	}
}

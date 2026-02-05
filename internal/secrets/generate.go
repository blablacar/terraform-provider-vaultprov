package secrets

import (
	"crypto/ecdh"
	"crypto/rand"
)

func GenerateRandomSecret(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	return key, err
}

func GenerateCurve25519Keypair() ([]byte, []byte, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey.Bytes(), privateKey.Public().(*ecdh.PublicKey).Bytes(), nil

}

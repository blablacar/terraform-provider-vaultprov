package secrets

import "crypto/rand"

func GenerateRandomSecret(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	return key, err
}

package secrets

import (
	"crypto/ecdh"
	cryptorand "crypto/rand"
	mathrand "math/rand/v2"
	"reflect"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func TestRandomSecret_Length(t *testing.T) {
	for i := 0; i < 10; i++ {
		l := mathrand.IntN(2048)

		secret, err := GenerateRandomSecret(l)
		if err != nil {
			t.Fatal("error:", err)
		}

		if len(secret) != l {
			t.Fatalf("Wrong secret's length: %d. Expected: %d", len(secret), l)
		}
	}
}

func TestRandomSecret_Uniqueness(t *testing.T) {
	s1, err := GenerateRandomSecret(64)
	if err != nil {
		t.Fatal("error:", err)
	}

	s2, err := GenerateRandomSecret(64)
	if err != nil {
		t.Fatal("error:", err)
	}

	if reflect.DeepEqual(s1, s2) {
		t.Fatalf("Both secret are equal")
	}
}

func TestGenerateCurve25519Keypair_KeySizes(t *testing.T) {
	privateKey, publicKey, err := GenerateCurve25519Keypair()
	if err != nil {
		t.Fatalf("GenerateCurve25519Keypair() error = %v", err)
	}

	if len(privateKey) != 32 {
		t.Errorf("private key length = %d, want 32", len(privateKey))
	}

	if len(publicKey) != 32 {
		t.Errorf("public key length = %d, want 32", len(publicKey))
	}
}

func TestGenerateCurve25519Keypair_Uniqueness(t *testing.T) {
	priv1, pub1, err := GenerateCurve25519Keypair()
	if err != nil {
		t.Fatalf("GenerateCurve25519Keypair() first call error = %v", err)
	}

	priv2, pub2, err := GenerateCurve25519Keypair()
	if err != nil {
		t.Fatalf("GenerateCurve25519Keypair() second call error = %v", err)
	}

	if reflect.DeepEqual(priv1, priv2) {
		t.Error("private keys should be unique but are equal")
	}

	if reflect.DeepEqual(pub1, pub2) {
		t.Error("public keys should be unique but are equal")
	}
}

func TestGenerateCurve25519Keypair_PublicKeyDerivation(t *testing.T) {
	privateKey, publicKey, err := GenerateCurve25519Keypair()
	if err != nil {
		t.Fatalf("GenerateCurve25519Keypair() error = %v", err)
	}

	// Verify that the public key matches what we'd derive from the private key
	derivedPublicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519.X25519() error = %v", err)
	}

	if !reflect.DeepEqual(publicKey, derivedPublicKey) {
		t.Error("public key does not match derived public key from private key")
	}
}

func TestGenerateCurve25519Keypair_ECDH(t *testing.T) {
	// Generate two keypairs (Alice and Bob)
	alicePriv, alicePub, err := GenerateCurve25519Keypair()
	if err != nil {
		t.Fatalf("GenerateCurve25519Keypair() for Alice error = %v", err)
	}

	bobPriv, bobPub, err := GenerateCurve25519Keypair()
	if err != nil {
		t.Fatalf("GenerateCurve25519Keypair() for Bob error = %v", err)
	}

	// Perform ECDH: Alice computes shared secret with Bob's public key
	aliceShared, err := curve25519.X25519(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("Alice's ECDH operation error = %v", err)
	}

	// Perform ECDH: Bob computes shared secret with Alice's public key
	bobShared, err := curve25519.X25519(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("Bob's ECDH operation error = %v", err)
	}

	// Both shared secrets should be identical
	if !reflect.DeepEqual(aliceShared, bobShared) {
		t.Error("ECDH shared secrets do not match")
	}

	// Shared secret should be 32 bytes
	if len(aliceShared) != 32 {
		t.Errorf("shared secret length = %d, want 32", len(aliceShared))
	}
}

func TestGenerateCurve25519Keypair_EncryptDecrypt(t *testing.T) {
	// Generate keypairs for sender and receiver
	senderPriv, senderPub, err := GenerateCurve25519Keypair()
	if err != nil {
		t.Fatalf("GenerateCurve25519Keypair() for sender error = %v", err)
	}

	receiverPriv, receiverPub, err := GenerateCurve25519Keypair()
	if err != nil {
		t.Fatalf("GenerateCurve25519Keypair() for receiver error = %v", err)
	}

	// Sender computes shared secret
	senderShared, err := curve25519.X25519(senderPriv, receiverPub)
	if err != nil {
		t.Fatalf("sender ECDH error = %v", err)
	}

	// Receiver computes shared secret
	receiverShared, err := curve25519.X25519(receiverPriv, senderPub)
	if err != nil {
		t.Fatalf("receiver ECDH error = %v", err)
	}

	// Create AEAD cipher using shared secret
	aead, err := chacha20poly1305.New(senderShared)
	if err != nil {
		t.Fatalf("chacha20poly1305.New() error = %v", err)
	}

	// Test message
	plaintext := []byte("Hello, this is a secret message for Curve25519 test!")

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := cryptorand.Read(nonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Decrypt using receiver's shared secret
	receiverAead, err := chacha20poly1305.New(receiverShared)
	if err != nil {
		t.Fatalf("chacha20poly1305.New() for receiver error = %v", err)
	}

	decrypted, err := receiverAead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("decryption error = %v", err)
	}

	// Verify decrypted message matches original
	if !reflect.DeepEqual(plaintext, decrypted) {
		t.Errorf("decrypted message does not match original.\nGot: %s\nWant: %s", decrypted, plaintext)
	}
}

func TestGenerateCurve25519Keypair_ECDHWithStandardLibrary(t *testing.T) {
	// Generate a keypair using our function
	ourPriv, ourPub, err := GenerateCurve25519Keypair()
	if err != nil {
		t.Fatalf("GenerateCurve25519Keypair() error = %v", err)
	}

	// Generate a keypair using crypto/ecdh directly
	standardPriv, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("ecdh.X25519().GenerateKey() error = %v", err)
	}

	// Reconstruct our private key as ecdh.PrivateKey
	ourPrivKey, err := ecdh.X25519().NewPrivateKey(ourPriv)
	if err != nil {
		t.Fatalf("ecdh.X25519().NewPrivateKey() error = %v", err)
	}

	// Reconstruct standard public key bytes
	standardPub := standardPriv.PublicKey().Bytes()

	// Perform ECDH: our key with standard public key
	sharedSecret1, err := curve25519.X25519(ourPriv, standardPub)
	if err != nil {
		t.Fatalf("ECDH with our key error = %v", err)
	}

	// Perform ECDH: standard key with our public key
	sharedSecret2, err := curve25519.X25519(standardPriv.Bytes(), ourPub)
	if err != nil {
		t.Fatalf("ECDH with standard key error = %v", err)
	}

	// Both shared secrets should match
	if !reflect.DeepEqual(sharedSecret1, sharedSecret2) {
		t.Error("ECDH with standard library key does not produce matching shared secret")
	}

	// Verify using crypto/ecdh ECDH method
	standardPubKey, err := ecdh.X25519().NewPublicKey(ourPub)
	if err != nil {
		t.Fatalf("ecdh.X25519().NewPublicKey() error = %v", err)
	}

	sharedViaECDH, err := standardPriv.ECDH(standardPubKey)
	if err != nil {
		t.Fatalf("standardPriv.ECDH() error = %v", err)
	}

	if !reflect.DeepEqual(sharedSecret1, sharedViaECDH) {
		t.Error("shared secret from curve25519.X25519 does not match crypto/ecdh.ECDH")
	}

	// Also test the reverse
	sharedViaECDH2, err := ourPrivKey.ECDH(standardPriv.PublicKey())
	if err != nil {
		t.Fatalf("ourPrivKey.ECDH() error = %v", err)
	}

	if !reflect.DeepEqual(sharedSecret1, sharedViaECDH2) {
		t.Error("shared secret from our key ECDH does not match expected value")
	}
}

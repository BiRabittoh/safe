package safe

import (
	"testing"
)

func TestSafeEncryptDecrypt(t *testing.T) {
	// Test data
	password := "thisis32bitlongpassphraseimusing" // Example 32-byte password
	plaintext := "This is a secret"

	// Initialize Safe instance with a specific password
	safe := NewSafe(password)

	// Encrypt plaintext
	ciphertextHex := safe.Encrypt(plaintext)

	// Decrypt ciphertext
	decryptedPlaintext, err := safe.Decrypt(ciphertextHex)
	if err != nil {
		t.Error(err)
	}

	// Verify if the decrypted plaintext matches the original plaintext
	if plaintext != decryptedPlaintext {
		t.Errorf("Decrypt(Encrypt(%s)) = %s; want %s", plaintext, decryptedPlaintext, plaintext)
	}
}

func TestSafeWithRandomPassword(t *testing.T) {
	// Initialize Safe instance with a random password
	safe := NewSafe("")

	// Test plaintext
	plaintext := "Hello, world!"

	// Encrypt plaintext
	ciphertextHex := safe.Encrypt(plaintext)

	// Decrypt ciphertext
	decryptedPlaintext, err := safe.Decrypt(ciphertextHex)
	if err != nil {
		t.Error(err)
	}

	// Verify if the decrypted plaintext matches the original plaintext
	if decryptedPlaintext != plaintext {
		t.Errorf("Decrypt(Encrypt(%s)) = %s; want %s", plaintext, decryptedPlaintext, plaintext)
	}
}

func TestSafeWithBadInput(t *testing.T) {
	// Test data
	password := "thisis32bitlongpassphraseimusing" // Example 32-byte password
	plaintext := "This is a secret"

	// Initialize Safe instance with a specific password
	safe := NewSafe(password)

	// Encrypt plaintext
	ciphertextHex := safe.Encrypt(plaintext)

	// Decrypt ciphertext
	_, err := safe.Decrypt(ciphertextHex + ".")
	if err == nil {
		t.Errorf("Decrypt(Encrypt(%s)+\".\") did not return an error", plaintext)
	}
}

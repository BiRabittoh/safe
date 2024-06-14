package safe

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	charsetLength = len(charset)
)

type Safe struct {
	c cipher.Block
}

func get32ByteString() string {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}

	passphrase := make([]byte, 32)
	for i := 0; i < 32; i++ {
		passphrase[i] = charset[int(randomBytes[i])%charsetLength]
	}
	return string(passphrase)

}

func NewSafe(password string) *Safe {
	if len(password) != 32 {
		println("WARNING: Using a random passphrase. Please use a fixed passphrase for production use.")
		password = get32ByteString()
	}

	key := []byte(password)
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return &Safe{c}
}

func (s *Safe) Encrypt(plaintext string) string {
	blockSize := s.c.BlockSize()
	plaintextBytes := []byte(plaintext)

	// PKCS#7 padding
	padding := blockSize - len(plaintextBytes)%blockSize
	padtext := append(plaintextBytes, bytes.Repeat([]byte{byte(padding)}, padding)...)

	ciphertext := make([]byte, blockSize+len(padtext))
	iv := ciphertext[:blockSize]
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(s.c, iv)
	mode.CryptBlocks(ciphertext[blockSize:], padtext)

	return hex.EncodeToString(ciphertext)
}

func (s *Safe) Decrypt(ciphertextHex string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	blockSize := s.c.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]

	mode := cipher.NewCBCDecrypter(s.c, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove padding
	padding := int(ciphertext[len(ciphertext)-1])
	if padding > blockSize || padding <= 0 {
		return "", errors.New("invalid padding")
	}

	return string(ciphertext[:len(ciphertext)-padding]), nil
}

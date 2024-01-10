package yii2security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

func GeneratePasswordHash(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	return string(hash)
}

func ValidatePassword(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func Encrypt(plaintext string, secret string, byPassword bool) (*[]byte, error) {
	salt := generateRandomBytes(16)
	iv := generateRandomBytes(16)

	var key []byte
	var err error

	if byPassword {
		key = derivePassword([]byte(secret), salt, nil)
	} else { // default is encryptByPassword
		key, err = deriveKey([]byte(secret), salt, nil)
		if err != nil {
			return nil, err
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintextBytes := []byte(plaintext)
	padText := padData(plaintextBytes)

	ciphertext := make([]byte, len(padText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padText)

	sha, err := generateAuthHash(append(iv, ciphertext...), key)
	if err != nil {
		return nil, err
	}
	fmt.Println(sha)

	result := append(salt, []byte(sha)...)
	result = append(result, iv...)
	result = append(result, ciphertext...)

	return &result, nil
}

func Decrypt(encoded []byte, secret string, byPassword bool) (string, error) {
	salt := encoded[:16]
	expectedHash := string(encoded[16:80])
	iv := encoded[80:96]
	ciphertext := encoded[96:]

	var key []byte
	var err error

	if byPassword {
		key = derivePassword([]byte(secret), salt, nil)
	} else { // default is encryptByPassword
		key, err = deriveKey([]byte(secret), salt, nil)
		if err != nil {
			return "", err
		}
	}
	sha, err := generateAuthHash(append(iv, ciphertext...), key)
	if err != nil {
		return "", err
	}

	if sha != string(expectedHash) {
		return "", fmt.Errorf("invalid HMAC_256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	return string(unpadData(decrypted)), nil
}

func generateAuthHash(data []byte, key []byte) (string, error) {
	authKey, err := deriveKey(key, nil, []byte("AuthorizationKey"))
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, authKey)
	mac.Write(data)
	sha := hex.EncodeToString(mac.Sum(nil))
	return sha, nil
}

func generateRandomBytes(size int) []byte {
	bytes := make([]byte, size)
	io.ReadFull(rand.Reader, bytes)
	return bytes
}

func deriveKey(secret []byte, salt []byte, info []byte) ([]byte, error) {
	keyHkdf := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, 16)
	_, err := keyHkdf.Read(key)
	return key, err
}

func derivePassword(secret []byte, salt []byte, info []byte) []byte {
	return pbkdf2.Key(secret, salt, 100000, 16, sha256.New)
}

func padData(data []byte) []byte {
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	padText := append(data, byte(padding))
	return append(padText, bytes.Repeat([]byte{byte(padding)}, padding-1)...)
}

func unpadData(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

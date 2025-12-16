package yii2security

import "testing"

func TestEncryptDecryptByKey(t *testing.T) {
	plaintext := "hello world"
	secret := "my-secret"

	ciphertext, err := Encrypt(plaintext, secret, false)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if ciphertext == nil || len(*ciphertext) == 0 {
		t.Fatalf("Encrypt returned empty ciphertext")
	}

	decrypted, err := Decrypt(*ciphertext, secret, false)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("Decrypt returned %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptByPassword(t *testing.T) {
	plaintext := "secret data"
	password := "P@ssw0rd!"

	ciphertext, err := Encrypt(plaintext, password, true)
	if err != nil {
		t.Fatalf("Encrypt by password returned error: %v", err)
	}

	decrypted, err := Decrypt(*ciphertext, password, true)
	if err != nil {
		t.Fatalf("Decrypt by password returned error: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("Decrypt returned %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptDetectsTampering(t *testing.T) {
	plaintext := "integrity check"
	secret := "hmac-secret"

	ciphertext, err := Encrypt(plaintext, secret, false)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	data := *ciphertext
	data[len(data)-1] ^= 0xFF // mutate ciphertext to break HMAC validation

	if _, err := Decrypt(data, secret, false); err == nil {
		t.Fatalf("Decrypt succeeded on tampered data, expected error")
	}
}

func TestGeneratePasswordHashAndValidate(t *testing.T) {
	password := "Admin123!"

	hash := GeneratePasswordHash(password)
	if hash == "" {
		t.Fatalf("GeneratePasswordHash returned empty hash")
	}

	if !ValidatePassword(password, hash) {
		t.Fatalf("ValidatePassword returned false for correct password")
	}

	if ValidatePassword("wrong-password", hash) {
		t.Fatalf("ValidatePassword returned true for incorrect password")
	}
}

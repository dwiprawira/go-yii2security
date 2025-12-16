# 🔒 Yii2 Security (Golang)

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue.svg)](https://golang.org/)

Golang port of Yii2's `Security` component so Go services can decrypt, encrypt, and verify payloads produced by existing Yii2/PHP apps (and vice versa). See [Yii2 Security documentation](https://www.yiiframework.com/doc/api/2.0/yii-base-security).

## ✨ Features
- Yii2-compatible `encryptByKey` / `decryptByKey`.
- Yii2-compatible `encryptByPassword` / `decryptByPassword`.
- Password hashing/validation compatible with Yii2 `generatePasswordHash()` and `validatePassword()`.

## 📋 Requirements
- Go 1.21+

## 🚀 Install

```bash
go get github.com/dwiprawira/go-yii2security/yii2security
```

## 💻 Usage

```go
import (
    "encoding/base64"
    "fmt"

    "github.com/dwiprawira/go-yii2security/yii2security"
)

func main() {
    plaintext := "hello world"

    // Encrypt/decrypt using a raw key (Yii2::encryptByKey / decryptByKey)
    key := "my-secret"
    cipherKey, _ := yii2security.Encrypt(plaintext, key, false)
    fmt.Println("by key:", base64.StdEncoding.EncodeToString(*cipherKey))
    plainKey, _ := yii2security.Decrypt(*cipherKey, key, false)
    fmt.Println("decrypted (key):", plainKey)

    // Encrypt/decrypt using a password (Yii2::encryptByPassword / decryptByPassword)
    password := "P@ssw0rd!"
    cipherPw, _ := yii2security.Encrypt(plaintext, password, true)
    fmt.Println("by password:", base64.StdEncoding.EncodeToString(*cipherPw))
    plainPw, _ := yii2security.Decrypt(*cipherPw, password, true)
    fmt.Println("decrypted (password):", plainPw)

    // Yii2-style password hashing
    hash := yii2security.GeneratePasswordHash(password)
    fmt.Println("hash:", hash)
    fmt.Println("valid:", yii2security.ValidatePassword(password, hash))
}
```

## 🔧 API Overview
- `Encrypt(data, secret string, usePassword bool) (*[]byte, error)`
  - `usePassword=false` → Yii2 `encryptByKey` (HKDF-based key derivation).
  - `usePassword=true`  → Yii2 `encryptByPassword` (PBKDF2-based derivation).
- `Decrypt(cipher []byte, secret string, usePassword bool) (string, error)`
  - Matches the corresponding Yii2 decrypt functions for the chosen derivation.
- `GeneratePasswordHash(password string) string`
- `ValidatePassword(password, hash string) bool`

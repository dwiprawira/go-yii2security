# Yii2 Security Module for Golang

## Overview
This repository houses a Golang implementation of the Yii2 security module, designed to seamlessly transition PHP-based Yii2 applications to the Golang environment.

## Example Usage

```go
package main

import (
	"fmt"
	"encoding/base64"
	"github.com/dwiprawira/go-yii2security/yii2security"
)

func main() {
	secret := "secret"
	data := "hello world????????!!"

	// Encrypt
	encryptedData, _ := yii2security.Encrypt(data, secret, false)
	
	// Print base64 of encryptedData
	fmt.Println(base64.StdEncoding.EncodeToString(*encryptedData))

	// Decrypt
	decrypted, _ := yii2security.Decrypt(*encryptedData, secret, false)
	fmt.Println(decrypted)

	// Generate and Validate Password
	passwordHash := yii2security.GeneratePasswordHash("Hello!!!")
	fmt.Println(passwordHash)

	if yii2security.ValidatePassword("Hello!!!", passwordHash) {
		fmt.Println("password correct!!")
	} else {
		fmt.Println("password incorrect!!")
	}
}

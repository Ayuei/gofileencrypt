package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
)

var decryptFlag bool
var encryptFlag bool
var filePath string
var keyPath string
var generateKey bool
var fileData []byte
var outData []byte
var key []byte

// Pads the data and used for authentication
var additionalData = []byte("Senectus massa tortor placerat lectus lacus donec scelerisque lacus")

func init(){
	flag.BoolVar(&decryptFlag, "decrypt", false, "Decrypt option flag")
	flag.BoolVar(&encryptFlag, "encrypt", false, "Encrypt option flag")
	flag.StringVar(&filePath, "fp", "", "Path to file")
	flag.StringVar(&keyPath, "kp", "", "Path to key")
	flag.BoolVar(&generateKey, "generate-key", false, "Generate a key and save to given fp")
}

func generate() error {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}

	fmt.Println("Generated key and saved to", filePath)
	err := ioutil.WriteFile(filePath, key, 600)

	return err
}

func encrypt() {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Block cipher:", err)
		return
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println("Cipher:", err)
		return
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
		return
	}

	outData = gcm.Seal(nonce, nonce, fileData, additionalData)
}

func decrypt() {
	c, _ := aes.NewCipher(key)

	gcm, _ := cipher.NewGCM(c)

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := fileData[:nonceSize], fileData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)

	if err != nil {
		fmt.Println("This file doesn't look like its encrypted:", err)
		return
	}

	outData = plaintext
}

func main() {
	flag.Parse()

	if generateKey && (decryptFlag || encryptFlag) {
		fmt.Println("When generating a key, decryption or encryption is not allowed.")
		return
	}

	if !generateKey && !decryptFlag && !encryptFlag {
		fmt.Println("Usage Encrypt/Decrypt: gofileencrypt [-encrypt/-decrypt] -fp [path-to-file] -kp [path-to-key-file]")
		fmt.Println("Usage Generate Key: gofileencrypt [-generate_key] -fp [path-to-save-key]")
		return
	}

	if decryptFlag && encryptFlag {
		fmt.Println("Only one encrypt or decrypt allowed, not both")
		return
	}

	if generateKey {
		if len(filePath) == 0 {
			fmt.Println("Must supply a file path to save the key")
			return
		}
		err := generate()

		if err != nil {
			fmt.Println("Error:", err)
		}
		return
	} else {
		if len(keyPath) == 0 {
			fmt.Println("Must supply a key file path if not generating one")
			return
		}

		_, err  := ioutil.ReadFile(keyPath)
		if err != nil {
			fmt.Println("Cannot open file:", err)
			return
		}
	}

	if len(filePath) == 0 {
		fmt.Println("File path not specified")
		return
	} else {
		var err error
		fileData, err = ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Println("Cannot open file:", err)
			return
		}
	}

	if len(keyPath) == 0 {
		fmt.Println("Key path not specified")
		return
	} else {
		var err error
		key, err = ioutil.ReadFile(keyPath)
		if err != nil {
			fmt.Println("Cannot open file:", err)
			return
		}
	}

	if encryptFlag {
		encrypt()
		if err := ioutil.WriteFile(filePath+".encrypt", outData, 600); err != nil {
			fmt.Println("Error writing encrypted file", err)
			return
		}
		fmt.Println("Encrypted file to", filePath+".encrypt")
	}

	if decryptFlag {
		decrypt()
		if err := ioutil.WriteFile(strings.TrimSuffix(filePath, ".encrypt"), outData, 600); err != nil {
			fmt.Println("Error writing encrypted file", err)
			return
		}
		fmt.Println("Decrypted file to", strings.TrimSuffix(filePath, ".encrypt"))
	}
}

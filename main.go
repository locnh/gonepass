package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	gosxnotifier "github.com/deckarep/gosx-notifier"
	"golang.design/x/clipboard"
	"golang.org/x/term"
)

func main() {

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err.Error())
	}

	encrypted, err := os.ReadFile(userHomeDir + "/.gonepass/encrypted")
	if err != nil {
		panic(err.Error())
	}

	password, err := readPassword()
	if err != nil {
		panic(err.Error())
	}

	key := hex.EncodeToString(password)

	decrypted := decrypt(string(encrypted), key)

	// Backup clipboard
	bakClipboard := clipboard.Read(clipboard.FmtText)

	// Write clipboard
	clipboard.Write(clipboard.FmtText, []byte(decrypted))
	notifyUser("Master Password", "Copied to the clipboard")

	time.Sleep(10 * time.Second)

	// Restore backup clipboard
	clipboard.Write(clipboard.FmtText, []byte(bakClipboard))
	notifyUser("Clipboard Contents Restored", "Prior clipboard restored")
}

func notifyUser(title string, subtitle string) {
	note := gosxnotifier.NewNotification(subtitle)
	note.Title = title
	note.Sender = "com.agilebits.onepassword7"
	note.Push()
}

func readPassword() ([]byte, error) {
	bytePassword := []byte(strings.Repeat("$", 32))

	fmt.Print("Enter Password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err.Error())
	}

	for i := 0; i < len(password); i++ {
		bytePassword[i] = password[i]
	}
	return bytePassword, nil
}

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func decrypt(encryptedString string, keyString string) (decryptedString string) {

	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}

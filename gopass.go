package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func Encrypt(key, data []byte) ([]byte, error) {
	key, salt, err := DeriveKey(key, nil)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ciphertext = append(ciphertext, salt...)
	return ciphertext, nil
}
func Decrypt(key, data []byte) ([]byte, error) {
	salt, data := data[len(data)-32:], data[:len(data)-32]
	key, _, err := DeriveKey(key, salt)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
func DeriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	key, err := scrypt.Key(password, salt, 1048576, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}
func onExit(servicesMap *map[string][]byte, masterPasswd []byte) {

	var serviceBuff []byte
	var passwdBuff []byte
	for service, passwd := range *servicesMap {
		serviceBuff = append(serviceBuff, []byte(service+"\n")...)
		passwdBuff = append(passwdBuff, passwd...)
		passwdBuff = append(passwdBuff, byte('\n'))
	}
	passData, err := Encrypt(masterPasswd, passwdBuff)
	if err != nil {
		panic(err)
	}
	serviceData, err := Encrypt(masterPasswd, serviceBuff)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("data/pass", passData, 0644)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("data/services", serviceData, 0644)
	if err != nil {
		panic(err)
	}

}
func populate(servicesMap *map[string][]byte, masterPasswd []byte) error {
	// proper file check
	if _, err := os.Stat("data"); !os.IsNotExist(err) {
		_, passErr := os.Stat("data/pass")
		_, serviceErr := os.Stat("data/services")
		if os.IsNotExist(passErr) || os.IsNotExist(serviceErr) {
			return errors.New("init error")
		}
		data, err := ioutil.ReadFile("data/pass")
		if err != nil {
			panic(err)
		}
		data, err = Decrypt(masterPasswd, data)
		if err != nil {
			panic(err)
		}
		passwords := bytes.Split(data, []byte("\n"))
		data, err = ioutil.ReadFile("data/services")
		if err != nil {
			panic(err)
		}
		data, err = Decrypt(masterPasswd, data)
		if err != nil {
			panic(err)
		}
		services := bytes.Split(data, []byte("\n"))
		if len(passwords) != len(services) {
			log.Fatal(errors.New("wtf?"))
		}
		for index, service := range services {
			(*servicesMap)[string(service)] = passwords[index]
		}

		return nil
	}

	err := os.Mkdir("data", 0755)
	if err != nil {
		log.Fatal(err)
	}
	fd, err := os.OpenFile("data/pass", os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	err = fd.Close()
	if err != nil {
		log.Fatal(err)
	}
	fd, err = os.OpenFile("data/services", os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	err = fd.Close()
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func readString(reader *bufio.Reader) string {
	text, _ := reader.ReadString('\n')
	// convert CRLF to LF
	text = strings.Replace(text, "\r\n", "", -1)
	text = strings.Replace(text, "\n", "", -1)
	return text
}

func main() {
	services := make(map[string][]byte)
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter master text")
	text := readString(reader)
	masterPasswd := []byte(text)

	err := populate(&services, masterPasswd)
	if err != nil {
		log.Fatal(err)
	}
	defer onExit(&services, masterPasswd)

	for {
		fmt.Println("Enter service name or 'exit' to exit")
		serviceName := readString(reader)
		if strings.Compare(serviceName, "exit") == 0 {
			break
		}
		service_pass, ok := services[serviceName]
		if ok {
			data, err := Decrypt(masterPasswd, service_pass)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s: %s\n", serviceName, data)
			continue
		}
		fmt.Println("Unknown service, create a new password? y/n")
		char := readString(reader)
		if strings.Compare(char, "y") == 0 {
			fmt.Printf("Service: %s. Enter password:", serviceName)
			passwd := readString(reader)
			encPasswd, err := Encrypt(masterPasswd, []byte(passwd))
			if err != nil {
				log.Fatal(err)
			}
			services[serviceName] = encPasswd
		}
		continue
	}
}

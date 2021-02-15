package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"test.com/gopasscrypto"
)

var splitBytes = []byte("splitSequense")

func onExit(servicesMap *map[string][]byte, masterPasswd []byte) {

	var serviceBuff []byte
	var passwdBuff []byte
	for service, passwd := range *servicesMap {
		serviceBuff = append(serviceBuff, []byte(service+"\n")...)
		passwdBuff = append(passwdBuff, passwd...)
		passwdBuff = append(passwdBuff, splitBytes...)
	}
	passData, err := gopasscrypto.Encrypt(masterPasswd, passwdBuff)
	if err != nil {
		panic(err)
	}
	serviceData, err := gopasscrypto.Encrypt(masterPasswd, serviceBuff)
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
		data, err = gopasscrypto.Decrypt(masterPasswd, data)
		if err != nil {
			panic(err)
		}
		passwords := bytes.Split(data, splitBytes)
		data, err = ioutil.ReadFile("data/services")
		if err != nil {
			panic(err)
		}
		data, err = gopasscrypto.Decrypt(masterPasswd, data)
		if err != nil {
			panic(err)
		}
		services := bytes.Split(data, []byte("\n"))
		if len(passwords) != len(services) {
			log.Fatal(errors.New("wtf?"), services, passwords)
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
	fmt.Println("Enter master password")
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
		servicePass, ok := services[serviceName]
		if ok {
			data, err := gopasscrypto.Decrypt(masterPasswd, servicePass)
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
			encPasswd, err := gopasscrypto.Encrypt(masterPasswd, []byte(passwd))
			if err != nil {
				log.Fatal(err)
			}
			services[serviceName] = encPasswd
		}
		continue
	}
}

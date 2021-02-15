package gopasscrypto

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
	"os"
)

var splitBytes = []byte("splitSequense")

func createDataDir() error {
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

type Keychain struct {
	servicePassMap map[string][]byte
	masterPasswd   []byte
}

func NewKeychain(masterPasswd []byte) *Keychain {
	keych := Keychain{servicePassMap: make(map[string][]byte), masterPasswd: masterPasswd}
	keych.populate()
	return &keych
}

func (keych *Keychain) readAnddecryptFile(fileName string) ([]byte, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	data, err = decrypt(keych.masterPasswd, data)
	if err != nil {
		panic(err)
	}
	return data, err
}

func (keych *Keychain) populate() error {
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		return createDataDir()
	}

	_, passErr := os.Stat("data/pass")
	_, serviceErr := os.Stat("data/services")
	if os.IsNotExist(passErr) || os.IsNotExist(serviceErr) {
		return errors.New("init error")
	}
	data, _ := keych.readAnddecryptFile("data/pass")
	passwords := bytes.Split(data, splitBytes)

	data, _ = keych.readAnddecryptFile("data/services")
	services := bytes.Split(data, []byte("\n"))

	if len(passwords) != len(services) {
		log.Fatal(errors.New("wtf?"), services, passwords)
	}

	for index, service := range services {
		(keych.servicePassMap)[string(service)] = passwords[index]
	}
	return nil
}

func (keych *Keychain) DumpKeychain() {

	var serviceBuff []byte
	var passwdBuff []byte
	for service, passwd := range keych.servicePassMap {
		serviceBuff = append(serviceBuff, []byte(service+"\n")...)
		passwdBuff = append(passwdBuff, passwd...)
		passwdBuff = append(passwdBuff, splitBytes...)
	}
	passData, err := encrypt(keych.masterPasswd, passwdBuff)
	if err != nil {
		panic(err)
	}
	serviceData, err := encrypt(keych.masterPasswd, serviceBuff)
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

func (keych *Keychain) GetServicePass(service string) ([]byte, bool) {
	servicePass, ok := keych.servicePassMap[service]
	if ok {
		data, err := decrypt(keych.masterPasswd, servicePass)
		if err != nil {
			log.Fatal(err)
		}
		return data, true
	}
	return nil, false
}

func (keych *Keychain) UpdatePass(service string, passwd []byte) error {
	encPasswd, err := encrypt(keych.masterPasswd, passwd)
	if err != nil {
		log.Fatal(err)
	}
	keych.servicePassMap[service] = encPasswd
	return nil

}

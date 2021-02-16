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

func (keych *Keychain) readAndDecryptFile(fileName string, ch chan []byte) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	data, err = decrypt(keych.masterPasswd, data)
	if err != nil {
		panic(err)
	}
	ch <- data
}

func (keych *Keychain) ecnryptAndWriteFile(fileName string, data *[]byte, ch chan int) {
	encrData, err := encrypt(keych.masterPasswd, *data)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(fileName, encrData, 0644)
	if err != nil {
		panic(err)
	}
	close(ch)
}

func (keych *Keychain) populate() error {
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		return createDataDir()
	}
	servicesCh := make(chan []byte)
	passCh := make(chan []byte)

	_, passErr := os.Stat("data/pass")
	_, serviceErr := os.Stat("data/services")
	if os.IsNotExist(passErr) || os.IsNotExist(serviceErr) {
		return errors.New("init error")
	}
	go keych.readAndDecryptFile("data/pass", passCh)
	go keych.readAndDecryptFile("data/services", servicesCh)

	passData := <-passCh
	servicesData := <-servicesCh
	passwords := bytes.Split(passData, splitBytes)
	services := bytes.Split(servicesData, []byte("\n"))

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
	passCh := make(chan int)
	servicesCh := make(chan int)
	go keych.ecnryptAndWriteFile("data/pass", &passwdBuff, passCh)
	go keych.ecnryptAndWriteFile("data/services", &serviceBuff, servicesCh)
	_ = <-passCh
	_ = <-servicesCh
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

func (keych *Keychain) HasPass(service string) bool {
	_, ok := keych.servicePassMap[service]
	return ok
}

func (keych *Keychain) UpdatePass(service string, passwd []byte) error {
	encPasswd, err := encrypt(keych.masterPasswd, passwd)
	if err != nil {
		log.Fatal(err)
	}
	keych.servicePassMap[service] = encPasswd
	return nil

}

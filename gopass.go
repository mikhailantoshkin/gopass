package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"test.com/gopasscrypto"
)

func readString(reader *bufio.Reader) string {
	text, _ := reader.ReadString('\n')
	// convert CRLF to LF
	text = strings.Replace(text, "\r\n", "", -1)
	text = strings.Replace(text, "\n", "", -1)
	return text
}

func presentChoise(text, truthfullChoise string, reader *bufio.Reader) (string, bool) {
	fmt.Println(text)
	resp := readString(reader)
	return resp, strings.Compare(resp, truthfullChoise) == 0
}

func updatePassPrompt(serviceName string, reader *bufio.Reader, keych *gopasscrypto.Keychain) error {
	fmt.Printf("Service: %s. Enter password: ", serviceName)
	passwd := readString(reader)
	keych.UpdatePass(serviceName, []byte(passwd))
	return nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter master password")
	text := readString(reader)
	masterPasswd := []byte(text)

	keych := gopasscrypto.NewKeychain(masterPasswd)
	defer keych.DumpKeychain()

	for {
		serviceName, shouldExit := presentChoise("Enter service name or 'exit' to exit", "exit", reader)
		if shouldExit {
			break
		}
		ok := keych.HasPass(serviceName)
		if ok {
			choise, _ := presentChoise("Please choose:\n1 Show password\n2 Change password", "", reader)
			if strings.Compare(choise, "1") == 0 {
				servicePass, _ := keych.GetServicePass(serviceName)
				fmt.Printf("%s: %s\n", serviceName, servicePass)
			} else if strings.Compare(choise, "2") == 0 {
				updatePassPrompt(serviceName, reader, keych)
			} else {
				fmt.Printf("Stop joking around pls")
			}
			continue

		}
		_, createNew := presentChoise("Unknown service, create a new password? y/n", "y", reader)
		if createNew {
			updatePassPrompt(serviceName, reader, keych)
		}
		continue
	}
}

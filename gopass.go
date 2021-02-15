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
		servicePass, ok := keych.GetServicePass(serviceName)
		if ok {
			fmt.Printf("%s: %s\n", serviceName, servicePass)
			continue
		}
		_, createNew := presentChoise("Unknown service, create a new password? y/n", "y", reader)
		if createNew {
			fmt.Printf("Service: %s. Enter password: ", serviceName)
			passwd := readString(reader)
			keych.UpdatePass(serviceName, []byte(passwd))
		}
		continue
	}
}

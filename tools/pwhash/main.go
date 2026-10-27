// Command pwhash prints an Argon2id hash in the format the panel stores, for
// out-of-band account recovery (see docs/operations.md §10). The password is
// read from stdin so it never lands in shell history or the process list.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(os.Stderr, "usage: pwhash < new-password  (reads one line from stdin)")
		os.Exit(2)
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		fmt.Fprintln(os.Stderr, "pwhash: refusing an empty password")
		os.Exit(2)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash:", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}

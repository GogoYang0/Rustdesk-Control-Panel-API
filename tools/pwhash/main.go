// Command pwhash prints an Argon2id hash in the format the panel stores, for
// out-of-band account recovery (see docs/operations.md §10). It handles one
// secret at a time and reads the password from argv only; the value is never
// written anywhere but stdout.
package main

import (
	"fmt"
	"os"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] == "" {
		fmt.Fprintln(os.Stderr, "usage: pwhash <new-password>")
		os.Exit(2)
	}
	hash, err := auth.HashPassword(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash:", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}

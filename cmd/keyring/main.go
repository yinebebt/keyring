package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/yinebebt/keyring"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	file := fs.String("file", "keys.json", "path to KeySet JSON file (one per service)")
	grace := fs.Duration("grace", 24*time.Hour, "grace period after rotation")
	_ = fs.Parse(os.Args[2:])

	store := keyring.NewFileStore(*file)
	kr := keyring.New(store, *grace)

	ctx := context.Background()

	var ks keyring.KeySet
	var err error
	switch os.Args[1] {
	case "rotate":
		ks, err = kr.Rotate(ctx)
	case "status":
		ks, err = kr.Status(ctx)
	case "revoke":
		ks, err = kr.Revoke(ctx)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		exitErr(err)
	}
	// Only rotate prints a key, and only the new one, on stdout.
	if os.Args[1] == "rotate" {
		fmt.Println(ks.Current)
	}
	printState(ks, time.Now())
}

func printState(ks keyring.KeySet, now time.Time) {
	state := ks.State(now)
	if state == keyring.StateGrace {
		fmt.Fprintf(os.Stderr, "%s: previous key valid until %s\n", state, ks.GraceUntil.Format(time.RFC3339))
		return
	}
	fmt.Fprintln(os.Stderr, state)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  keyring rotate [-file keys.json] [-grace 24h]
  keyring status [-file keys.json]
  keyring revoke [-file keys.json]

`)
}

func exitErr(err error) {
	fmt.Fprintf(os.Stderr, "keyring: %v\n", err)
	os.Exit(1)
}

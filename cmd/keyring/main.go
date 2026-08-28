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

	switch os.Args[1] {
	case "rotate":
		ks, err := kr.Rotate(ctx)
		if err != nil {
			exitErr(err)
		}
		printKeySet(ks, time.Now())
	case "status":
		ks, err := kr.Status(ctx)
		if err != nil {
			exitErr(err)
		}
		printKeySet(ks, time.Now())
	case "revoke":
		ks, err := kr.Revoke(ctx)
		if err != nil {
			exitErr(err)
		}
		printKeySet(ks, time.Now())
	default:
		usage()
		os.Exit(2)
	}
}

func printKeySet(ks keyring.KeySet, now time.Time) {
	fmt.Printf("state:   %s\n", ks.State(now))
	fmt.Printf("current: %s\n", ks.Current)
	if ks.Previous != "" {
		fmt.Printf("previous: %s\n", ks.Previous)
	}
	if ks.GraceUntil != nil {
		fmt.Printf("grace_until: %s\n", ks.GraceUntil.Format(time.RFC3339))
	}
	if ks.RotatedAt != nil {
		fmt.Printf("rotated_at:  %s\n", ks.RotatedAt.Format(time.RFC3339))
	}
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

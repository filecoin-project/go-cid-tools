package main

import (
	"bytes"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"

	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	blake2b "github.com/minio/blake2b-simd"
	"golang.org/x/crypto/sha3"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

var hashes map[string]func() hash.Hash

func init() {
	hashes = map[string]func() hash.Hash{
		"sha1":        sha1.New,
		"sha2-256":    sha256.New,
		"sha2-512":    sha512.New,
		"sha3-224":    sha3.New224,
		"sha3-256":    sha3.New256,
		"sha3-384":    sha3.New384,
		"sha3-512":    sha3.New512,
		"blake2b-256": blake2b.New256,
		"blake2b-512": blake2b.New512,
	}
}

func main() {
	quiet := flag.Bool("q", false, "be quiet")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: cidcheck [-1] <cid> {<file>|-}\n")
		os.Exit(1)
	}

	c, err := cid.Decode(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding cid %s: %s\n", args[0], err)
		os.Exit(1)
	}

	hi, err := multihash.Decode(c.Hash())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding multihash: %s\n", err)
		os.Exit(1)
	}

	hash, err := newHash(hi.Code)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating hash: %s\n", err)
		os.Exit(1)
	}

	var in io.Reader
	if args[1] == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening %s: %s\n", args[1], err)
			os.Exit(1)
		}
		defer f.Close()
		in = f
	}

	_, err = io.Copy(hash, in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error hashing input: %s\n", err)
		os.Exit(1)
	}

	digest := hash.Sum(nil)
	if !bytes.Equal(hi.Digest, digest) {
		fmt.Fprintf(os.Stderr, "hash mismatch\n")
		os.Exit(1)
	}

	if !*quiet {
		fmt.Println("OK")
	}
}

func newHash(code uint64) (hash.Hash, error) {
	name, ok := multihash.Codes[code]
	if !ok {
		return nil, fmt.Errorf("unknown multihash code: %d", code)
	}

	hash, ok := hashes[name]
	if !ok {
		return nil, fmt.Errorf("unsupported hash function: %s", name)
	}

	return hash(), nil
}

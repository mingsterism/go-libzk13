package main

import (
	"fmt"

	"github.com/mingsterism/go-libzk13/zkp"
)

func main() {
	// Create a new ZK13 instance with a 2048-bit prime
	zk13 := zkp.NewZK13("shared secret", 2048)

	// Generate a nonce for replay attack protection
	nonce, err := zkp.GenerateNonce(zk13.P())
	if err != nil {
		panic(err)
	}

	// Generate a zero-knowledge proof of set membership
	proof, err := zk13.Prover(nonce)
	if err != nil {
		panic(err)
	}

	// Verify the zero-knowledge proof of set membership
	isValid := zk13.Verifier(proof)
	fmt.Printf("Proof is valid: %v\n", isValid)
}

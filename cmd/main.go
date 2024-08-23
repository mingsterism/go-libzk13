package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/mingsterism/go-libzk13/zkp"
)

var allowedShapes = []string{"circle", "square", "triangle", "rectangle"}

func hashShape(shape string) string {
	hash := sha256.Sum256([]byte(shape))
	return fmt.Sprintf("%x", hash)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Start a goroutine with an HTTP server for runtime profiling
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// Enable CPU profiling
	f, err := os.Create("cpu.prof")
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	defer f.Close()
	if err := pprof.StartCPUProfile(f); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile()

	// Run tests
	err = runTests()
	if err != nil {
		log.Fatalf("Error running tests: %v", err)
	}

	// Memory profiling
	mf, err := os.Create("mem.prof")
	if err != nil {
		log.Fatal("could not create memory profile: ", err)
	}
	defer mf.Close()
	runtime.GC() // get up-to-date statistics
	if err := pprof.WriteHeapProfile(mf); err != nil {
		log.Fatal("could not write memory profile: ", err)
	}
}

func runTests() error {
	var errors []string

	// Test different prime lengths
	for _, bits := range []int{512, 1024, 2048, 2048 + 32} {
		fmt.Printf("Testing with prime length: %d bits\n", bits)

		secretShape := "circle"
		hashedShape := hashShape(secretShape)

		zk13 := zkp.NewZK13(hashedShape, bits)
		nonce := zk13.GenerateNonce()

		proof, err := zk13.Prover(nonce)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Error generating proof for %d bits: %v", bits, err))
			continue
		}

		fmt.Printf("Debug Info for %d bits:\n", bits)
		fmt.Printf("Nonce: %s\n", proof.Nonce.String())
		fmt.Printf("R: %s\n", proof.R.String())
		fmt.Printf("P: %s\n", proof.P.String())

		isValid := zk13.Verifier(proof)
		fmt.Printf("Verification with %d bits prime: %v\n", bits, isValid)

		if !isValid {
			errors = append(errors, fmt.Sprintf("Proof should be valid for %d bits", bits))
		}

		fmt.Println("------------------------------")
	}

	// Run timing attack test
	zk13 := zkp.NewZK13(hashShape("square"), 2048)
	nonce := zk13.GenerateNonce()
	proof, err := zk13.Prover(nonce)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error generating proof: %v", err))
	} else {
		isValid := zk13.Verifier(proof)
		if !isValid {
			errors = append(errors, "Proof should be valid in timing attack test")
		}

		// Modify the proof and verify that it is invalid
		proof.R.Add(proof.R, big.NewInt(1))
		isValid = zk13.Verifier(proof)
		if isValid {
			errors = append(errors, "Proof should be invalid after modification")
		}

		// Modify the nonce and verify that the proof is invalid
		proof.Nonce.Add(proof.Nonce, big.NewInt(1))
		isValid = zk13.Verifier(proof)
		if isValid {
			errors = append(errors, "Proof should be invalid with modified nonce")
		}
	}

	// Run replay attack test
	zk13 = zkp.NewZK13(hashShape("triangle"), 2048)
	nonce = zk13.GenerateNonce()
	proof, err = zk13.Prover(nonce)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error generating proof: %v", err))
	} else {
		isValid := zk13.Verifier(proof)
		if !isValid {
			errors = append(errors, "Proof should be valid in replay attack test")
		}

		// Use the same nonce to generate another proof
		proof2, err := zk13.Prover(nonce)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Error generating second proof: %v", err))
		} else {
			isValid = zk13.Verifier(proof2)
			if isValid {
				errors = append(errors, "Proof should be invalid when reusing nonce")
			} else {
				fmt.Println("Nonce reuse correctly detected")
			}
		}
	}

	if len(errors) > 0 {
		fmt.Println("The following tests failed:")
		for _, err := range errors {
			fmt.Println("- " + err)
		}
		return fmt.Errorf("Some tests failed")
	}

	fmt.Println("All tests passed successfully!")
	fmt.Println("Possible shapes:", allowedShapes)
	fmt.Println("The verifier only knows that the prover knows one of these shapes, but not which one")

	return nil
}

package zkp

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/zeebo/blake3"
)

const PubKeyRange = 2044 // Size of k, ensure the range is suitable

type ZK13 struct {
	p, g, q, Hs *big.Int
	usedNonces  map[string]bool
}

// NewZK13 initializes the ZK13 structure with a prime number, generator, and hashed secret.
// It addresses the correct handling of byte slices and ensures that parameters are securely generated.
func NewZK13(secretBaggage string, bits int) *ZK13 {
	var p *big.Int
	var err error
	z := &ZK13{}
	p, err = GenerateLargePrime(bits)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate a large prime: %v", err))
	}
	q, err := GenerateLargePrime(bits / 2)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate a large prime: %v", err))
	}
	g, err := GenerateGenerator(p, q)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate a generator: %v", err))
	}
	z.q = q
	z.g = g
	z.p = p
	if !z.ValidateParameters(big.NewInt(224)) {
		z.p = nil
		p, err = GenerateLargePrime(bits)
		z.p = p
	}
	hash := blake3.Sum512([]byte(secretBaggage))
	Hs := new(big.Int).SetBytes(hash[:])
	z.Hs = Hs
	z.usedNonces = make(map[string]bool)

	return z
}

type Proof struct {
	R, P, Nonce *big.Int
}

func (z *ZK13) Prover(nonce *big.Int) (*Proof, error) {
	k, err := rand.Int(rand.Reader, z.p) // Prover's random secret
	if err != nil {
		return nil, err
	}
	r := new(big.Int).Exp(z.g, k, z.p) // r = g^k mod p

	// Calculate P
	P := new(big.Int).Exp(z.g, nonce, z.p)
	P.Mul(P, new(big.Int).Exp(z.Hs, r, z.p))
	P.Mod(P, z.p)

	proof := &Proof{
		R:     r,
		P:     P,
		Nonce: nonce,
	}
	return proof, nil
}

func (z *ZK13) Verifier(proof *Proof) bool {
	fmt.Println("Debug Info in Verifier:")
	fmt.Printf("proof.Nonce: %s\n", proof.Nonce)
	fmt.Printf("z.p: %s\n", z.p)
	fmt.Printf("z.g: %s\n", z.g)
	fmt.Printf("z.Hs: %s\n", z.Hs)
	fmt.Printf("proof.R: %s\n", proof.R)
	fmt.Printf("proof.P: %s\n", proof.P)

	// Check for nonce reuse
	nonceStr := proof.Nonce.String()
	if z.usedNonces[nonceStr] {
		fmt.Println("Verification failed: Nonce reuse detected")
		return false
	}

	// Calculate expected value of P
	expectedP := new(big.Int).Exp(z.g, proof.Nonce, z.p)
	fmt.Printf("Initial expectedP: %s\n", expectedP)

	temp := new(big.Int).Exp(z.Hs, proof.R, z.p)
	expectedP.Mul(expectedP, temp)
	expectedP.Mod(expectedP, z.p)
	fmt.Printf("Final expectedP: %s\n", expectedP)

	// Check that P matches expected value
	if proof.P.Cmp(expectedP) != 0 {
		fmt.Println("Verification failed: proof.P != expectedP")
		return false
	}

	// Check that nonce is valid
	fmt.Println("Checking nonce validity")
	fmt.Printf("Nonce: %s\n", proof.Nonce)
	fmt.Printf("1 < Nonce: %v\n", proof.Nonce.Cmp(big.NewInt(1)) > 0)
	fmt.Printf("Nonce < q: %v\n", proof.Nonce.Cmp(z.q) < 0)
	if proof.Nonce.Cmp(big.NewInt(1)) <= 0 || proof.Nonce.Cmp(z.q) >= 0 {
		fmt.Println("Verification failed: Invalid nonce")
		return false
	}

	// Mark nonce as used
	z.usedNonces[nonceStr] = true

	fmt.Println("Verification passed")
	return true
}

func GenerateLargePrime(bit int) (*big.Int, error) {
	prime, err := rand.Prime(rand.Reader, bit)
	if err != nil {
		return nil, err
	}
	return prime, nil
}

// calculateR calculates r = g^k mod p.
func (z *ZK13) calculateR(k *big.Int) *big.Int {
	return new(big.Int).Exp(z.g, k, z.p)
}

// calculateF calculates F = Hs*k mod (p-1).
func (z *ZK13) calculateF(k *big.Int) *big.Int {
	pMinusOne := new(big.Int).Sub(z.p, big.NewInt(1))
	return new(big.Int).Mod(new(big.Int).Mul(z.Hs, k), pMinusOne)
}

// CalculateP calculates P = g^F mod p.
func (z *ZK13) CalculateP(F *big.Int) *big.Int {
	return new(big.Int).Exp(z.g, F, z.p)
}

func (z *ZK13) GenerateNonce() *big.Int {
	for {
		nonce, err := rand.Int(rand.Reader, z.q)
		if err != nil {
			continue
		}
		if nonce.Cmp(big.NewInt(1)) > 0 && nonce.Cmp(z.q) < 0 {
			return nonce
		}
	}
}

// randBigInt generates a random big integer within a specified range.
func randBigInt(max *big.Int) (*big.Int, error) {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return n, nil
}

type Verifier struct {
	k, r, F, P *big.Int
}

// GenerateGenerator generates a generator of the form g = h^((p-1)/q) where
// h is a random element in the field and q is a large prime factor of p-1.
func GenerateGenerator(p, q *big.Int) (*big.Int, error) {
	// Generate a random element h in the field
	h, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, err
	}
	// Ensure that h is not a multiple of q
	for h.Mod(h, q).Cmp(big.NewInt(0)) == 0 {
		h, err = rand.Int(rand.Reader, p)
		if err != nil {
			return nil, err
		}
	}
	// Compute g = h^((p-1)/q)
	pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
	pMinusOneOverQ := new(big.Int).Div(pMinusOne, q)
	g := new(big.Int).Exp(h, pMinusOneOverQ, p)
	return g, nil
}

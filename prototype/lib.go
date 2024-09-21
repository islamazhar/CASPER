package virtualwebauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
	"sort"

	"golang.org/x/crypto/pbkdf2"
)

type ByBytes [][]byte

// Implement the sort.Interface for ByBytes
func (b ByBytes) Len() int           { return len(b) }
func (b ByBytes) Less(i, j int) bool { return bytes.Compare(b[i], b[j]) < 0 }
func (b ByBytes) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }

// GenerateRandomBytes generates a random byte slice of the specified length.
func GenerateRandomBytes(length int) ([]byte, error) {
	// Create a byte slice of the given length
	bytes := make([]byte, length)

	// Fill the byte slice with random bytes from crypto/rand
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func GenDetectSecret(k int, kappa int) ByBytes {

	var W [][]byte
	for i := 0; i < k; i++ {
		randomBytes, err := GenerateRandomBytes(kappa)
		if err != nil {
			fmt.Println("Error generating random bytes:", err)
			panic("Error generating random bytes")
		}
		W = append(W, randomBytes)
	}
	return W

}

func GetHashValue(w []byte, eta int) []byte {

	// Create a byte buffer
	buf := new(bytes.Buffer)

	// Write the integer to the buffer in little-endian order
	err := binary.Write(buf, binary.LittleEndian, int32(eta))
	if err != nil {
		fmt.Println("Error:", err)
		panic("Error converting eta to byte string")
	}

	// Convert the buffer to a byte slice
	eta_bytes := buf.Bytes()
	data := append(w, eta_bytes...)

	// Create a new SHA-256 hash object
	hash := sha256.New()
	hash.Write(data)
	hashBytes := hash.Sum(nil)
	return hashBytes

}

func SelectRealSecret(W ByBytes, k int, eta int) int {

	var W_hash [][]byte
	for i := 0; i < len(W); i++ {
		hash_value := GetHashValue(W[i], eta)
		W_hash = append(W_hash, hash_value)
	}
	// sorting the hash value
	sort.Sort(ByBytes(W_hash))
	idx := eta % k
	return idx
}

func XorBytes(a, b []byte) []byte {
	// Ensure the two slices are of the same length
	if len(a) != len(b) {
		fmt.Printf("Error: byte slices must be of the same length but got %d and %d", len(a), len(b))
		return nil
	}

	// Create a result slice with the same length
	result := make([]byte, len(a))

	// XOR each byte in the slices
	for i := range a {
		result[i] = a[i] ^ b[i]
	}

	return result
}

func EncCred(w []byte, privateKey *ecdsa.PrivateKey, kappa int) ([]byte, []byte) {
	randomBytes, err := GenerateRandomBytes(kappa)
	if err != nil {
		panic("Error generating random bytes")
	}
	iterations := 6000
	u := pbkdf2.Key(w, randomBytes, iterations, kappa, sha256.New)
	privateKeyMasked := XorBytes(u, privateKey.D.Bytes())
	// fmt.Printf("u => %d\n", u)

	return privateKeyMasked, randomBytes

}

func DecCred(w []byte, privateKeyMasked []byte, kappa int, randomSeed []byte) *big.Int {

	iterations := 6000
	u := pbkdf2.Key(w, randomSeed, iterations, kappa, sha256.New)
	privateKeyDBytes := XorBytes(u, privateKeyMasked)

	// fmt.Printf("u => %d\n", u)

	D := new(big.Int)
	D.SetBytes(privateKeyDBytes)

	return D

}

// Modify the private key's D value
// newD := new(big.Int).SetInt64(12345) // Setting a new value for D
// privateKey1.D = newD

// privateKey1.PublicKey.X, privateKey1.PublicKey.Y = elliptic.P256().ScalarBaseMult(privateKey1.D.Bytes())

func VerifierGen(D *big.Int) *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("Error generating new keys")
	}
	privateKey.D = D
	// Recalculate the public key based on the new D value
	privateKey.PublicKey.X, privateKey.PublicKey.Y = elliptic.P256().ScalarBaseMult(privateKey.D.Bytes())
	return privateKey

}

func GenVerifierSet(W ByBytes, privateKeyMasked []byte, randomSeed []byte, kappa int) []Credential {
	iterations := 6000
	var creds []Credential
	for i := 0; i < len(W); i++ {
		u := pbkdf2.Key(W[i], randomSeed, iterations, kappa, sha256.New)
		privateKeyDBytes := XorBytes(u, privateKeyMasked)
		D := new(big.Int)
		D.SetBytes(privateKeyDBytes)
		candidate_privateKey := VerifierGen(D)

		key := &Key{Type: "ec2"}
		keyData, err := x509.MarshalPKCS8PrivateKey(candidate_privateKey)
		if err != nil {
			panic("Error in genVerifierSet")
		}
		key.signingKey, key.Data = newEC2SigningKeyWithPrivateKey(candidate_privateKey), keyData

		cred := Credential{}
		cred.ID = randomBytes(32)
		cred.Key = key

		creds = append(creds, cred)
	}
	return creds
}

// randomly sampel the k active decoy verifiers
func RandSampleK(creds []Credential, alpha float64) []Credential {
	// todo: need to seed the shuffle
	n := int(math.Ceil(alpha * float64(len(creds))))

	mrand.Shuffle(len(creds), func(i, j int) {
		creds[i], creds[j] = creds[j], creds[i]
	})

	// Return the first k elements
	if n > len(creds) {
		n = len(creds)
	}

	// var activeCredIDs [][]byte
	// for i := 0; i < n; i++ {
	// 	activeCredIDs = append(activeCredIDs, creds[i].ID)
	// }
	// return activeCredIDs
	// fmt.Println("len of len(creds)", len(creds), " n = ", n)
	return creds[:n]
}

func IsActiveCred(activeCreds []Credential, target []byte) bool {
	for _, c := range activeCreds {
		// Use bytes.Equal to compare slices
		if bytes.Equal(c.ID, target) {
			// println(c.ID, target)
			return true
		}
	}
	return false
}

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
	"io/ioutil"
	"math"
	"math/big"
	mrand "math/rand"
	"os"
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

	var W ByBytes
	for i := 0; i < k; i++ {
		randomBytes, err := GenerateRandomBytes(kappa)
		if err != nil {
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

	var W_hash ByBytes
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
	z, err := GenerateRandomBytes(kappa)
	if err != nil {
		panic("Error generating random bytes")
	}

	u := pbkdf2.Key(w, z, iterations, kappa, sha256.New)
	privateKeyMasked := XorBytes(u, privateKey.D.Bytes())
	// fmt.Printf("w => %d z = %d iterations = %d kappa = %d\n", w, z, iterations, kappa)
	// fmt.Printf("u => %d\n", u)

	return privateKeyMasked, z

}

func DecCred(w []byte, privateKeyMasked []byte, kappa int, z []byte) *big.Int {

	u := pbkdf2.Key(w, z, iterations, kappa, sha256.New)
	privateKeyDBytes := XorBytes(u, privateKeyMasked)
	// fmt.Printf("w => %d z = %d iterations = %d kappa = %d\n", w, z, iterations, kappa)

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

func GenVerifierSet(W ByBytes,
	privateKeyMasked []byte,
	randomSeed []byte,
	kappa int,
	i_star int,
	credID []byte) []Credential {

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

		if i_star == i {
			cred.ID = credID
		} else {
			cred.ID = credID
			// cred.ID = randomBytes(32)
		}
		cred.Key = key

		creds = append(creds, cred)
	}
	return creds
}

/* randomly sample the k active decoy verifiers; except for the i_star */

func RandSampleK(creds []Credential, alpha float64, i_star int) []int {

	n := int(math.Ceil(alpha * float64(len(creds))))

	numbers := make([]int, len(creds)-1)

	idx := 0

	for i := 0; i < len(creds); i++ {
		if i == i_star {
			continue
		} else {
			numbers[idx] = i
			idx = idx + 1
		}
	}

	mrand.Shuffle(len(numbers), func(i, j int) {
		numbers[i], numbers[j] = numbers[j], numbers[i]
	})

	randomNumbers := numbers[:n]

	return randomNumbers
}

/* writing to storage functions  start	*/
func WritePmsStorage(W ByBytes, randomSeed []byte, privateKeyMasked []byte, credID []byte) {
	WriteBytesFile(W, PmsFileName)
	WriteByteFile(randomSeed, PmsFileName)
	WriteByteFile(privateKeyMasked, PmsFileName)
	WriteByteFile(credID, PmsFileName)

}

func ReadPmsStorage(k int) (ByBytes, []byte, []byte, []byte) {
	fileContents := ReadBytesFile(PmsFileName)
	W, randomSeed, privateKeyMasked, credID := fileContents[0:k], fileContents[k], fileContents[k+1], fileContents[k+2]

	return W, randomSeed, privateKeyMasked, credID
}

func WriteBytesFile(writeBytes ByBytes, fileName string) {

	// Open the file in append mode. Create it if it doesn't exist.
	fo, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		panic(err)
	}
	defer fo.Close()

	for _, w := range writeBytes {
		_, err := fo.Write(w)
		if err != nil {
			panic(err)
		}
		fo.Write([]byte(Delimiter))
	}
}
func WriteByteFile(writeByte []byte, fileName string) {

	// Open the file in append mode. Create it if it doesn't exist.
	fo, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		panic(err)
	}
	defer fo.Close()
	fo.Write(writeByte)
	fo.Write([]byte(Delimiter))
}

func ReadBytesFile(fileName string) ByBytes {
	fileContents, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}

	contents := bytes.Split(fileContents, []byte(Delimiter))
	contents = removeEmptyStrings(contents)
	return contents
}

// Function to write a list of integers to a binary file
func writeIntegersToBinaryFile(fileName string, integers []int) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, i := range integers {
		if err := binary.Write(file, binary.LittleEndian, int32(i)); err != nil {
			return err
		}
	}

	return nil
}

func ReadRpStorage() ([]int, error) {

	file, err := os.Open(RpFileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var integers []int
	for {
		var i int32
		err := binary.Read(file, binary.LittleEndian, &i)
		if err != nil {
			break // Break the loop if we reach the end of the file or encounter an error
		}
		integers = append(integers, int(i))
	}
	return integers, nil
}

func WriteRpStorage(activeIDs []int) {
	writeIntegersToBinaryFile(RpFileName, activeIDs)
}

func removeEmptyStrings(data ByBytes) ByBytes {

	var result ByBytes
	for _, s := range data {
		if len(s) > 0 { // Only append non-empty elements
			result = append(result, s)
		}
	}
	return result
}

/*** writing to storage functions end ***/

func IsActiveDecoyCred(list []int, target int) bool {
	for _, value := range list {
		if value == target {
			return true
		}
	}
	return false
}

const (
	WebauthnDisplayName = "Example"
	WebauthnDomain      = "example.com"
	WebauthnOrigin      = "https://example.com"
	UserID              = "a987z"
	UserName            = "Alice"
	UserDisplayName     = "Alice"

	kappa      = 32   /* 128 bits of security */
	k          = 32   /* number of decoys */
	alpha      = 0.6  /* percentage of verifiers being marked */
	iterations = 6000 /* num of iterations for KDF */

	/* storage file names */
	PmsFileName = "storage/pms_passkeys.byte"
	RpFileName  = "storage/rp_passkeys.bin"
	Delimiter   = "|||"
)

// // randomly sampel the k active decoy verifiers
// func RandSampleK(creds []Credential, alpha float64) []Credential {
// 	// todo: need to seed the shuffle
// 	n := int(math.Ceil(alpha * float64(len(creds))))

// 	mrand.Shuffle(len(creds), func(i, j int) {
// 		creds[i], creds[j] = creds[j], creds[i]
// 	})

// 	// Return the first k elements
// 	if n > len(creds) {
// 		n = len(creds)
// 	}

// 	// var activeCredIDs [][]byte
// 	// for i := 0; i < n; i++ {
// 	// 	activeCredIDs = append(activeCredIDs, creds[i].ID)
// 	// }
// 	// return activeCredIDs
// 	// fmt.Println("len of len(creds)", len(creds), " n = ", n)
// 	return creds[:n]
// }

// func IsActiveCred(activeCreds []Credential, target []byte) bool {
// 	for _, c := range activeCreds {
// 		// Use bytes.Equal to compare slices
// 		if bytes.Equal(c.ID, target) {
// 			// println(c.ID, target)
// 			return true
// 		}
// 	}
// 	return false
// }

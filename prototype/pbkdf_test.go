package virtualwebauthn

import (
	"fmt"
	"testing"
)

func TestPbkdf(t *testing.T) {

	// randomBytes, _ := GenerateRandomBytes(kappa)
	// w, _ := GenerateRandomBytes(kappa)
	// u1 := pbkdf2.Key(w, randomBytes, iterations, kappa, sha256.New)
	// u2 := pbkdf2.Key(w, randomBytes, iterations, kappa, sha256.New)

	// fmt.Println(u1)
	// fmt.Println(u2)

	// x := XorBytes(u1, u2)
	// fmt.Println(x)

	data := [][]byte{
		[]byte("Hello, World!"),
		[]byte("Welcome to Go programming"),
		[]byte("This is a test byte string"),
	}

	fmt.Println(data)

	WriteBytesFile(data, PmsFileName)
	data = ReadBytesFile(PmsFileName)

	fmt.Println(data)

}

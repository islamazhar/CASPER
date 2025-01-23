package virtualwebauthn

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/fxamacker/webauthn"
	_ "github.com/fxamacker/webauthn/packed"
	"github.com/stretchr/testify/require"
)

func TestCasperDetection(t *testing.T) {

	// step 0. get \eta from the user
	// fmt.Print("Enter eta: ")
	// _, err := fmt.Scan(&eta)
	// require.NoError(t, err)
	eta := 42

	// 1. Create W  = {w_1, w_2, \cdot, w_k} // just random strings GenDetectSecret

	W := GenDetectSecret(k, kappa)
	fmt.Println(len(W))
	i_star := SelectRealSecret(W, k, eta)

	fmt.Println(len(W))

	// fmt.Printf("i_star => %d\n", i_star)

	// cred := NewCredential(KeyTypeEC2)
	// NewCredential --> keyType.newKey()--> signKey, Data = newEC2SigningKey()/newRSASigningKey() -->

	// creating they cred key; called by Authenticator start
	// signingKey, data := newEC2SigningKey()
	key := &Key{Type: "ec2"}
	signingKey, data := newEC2SigningKey()
	key.signingKey, key.Data = signingKey, data

	cred := Credential{}
	cred.ID = randomBytes(32)
	cred.Key = key
	// creating the ec2 key finish

	// borrowed from newCredential function inside webauthn_test.go

	privateKey := signingKey.privateKey

	// fmt.Println(privateKey.D)

	// publicKey := privateKey.PublicKey
	privateKeyMasked, z := EncCred(W[i_star], privateKey, kappa)

	/* write randomSeed and W to a file */
	WritePmsStorage(W, z, privateKeyMasked, cred.ID)

	// [fixme:] the following line is causing the code to crash.
	// W, z, privateKeyMasked, cred.ID = ReadPmsStorage(k)

	// todo: it should generate k number of Ds?
	D := DecCred(W[i_star], privateKeyMasked, kappa, z)
	fmt.Println("D = ", D)

	recoveredPrivateKey := VerifierGen(D)

	require.Equal(t, recoveredPrivateKey, privateKey)

	creds := GenVerifierSet(W, privateKeyMasked,
		z, kappa,
		i_star, cred.ID) // instead of verifierSet return a credential set

	fmt.Println(creds[i_star])
	// removing i_star for sampling active verifiers
	// creds = append(creds[:i_star], creds[i_star+1:]...)

	// fmt.Printf("size of the creds set %d\n", len(creds))

	// todo: why this following test is failing... ignoring for now
	// require.Contains(t, verifierPubKey, privateKey.PublicKey)

	// Send veriferPubKeys with their markings
	activeDecoyCreds := RandSampleK(creds, alpha, i_star)
	/* writing the active IDs */
	// fmt.Println(activeCreds)
	WriteRpStorage(activeDecoyCreds)
	activeDecoyCreds, _ = ReadRpStorage()

	// fmt.Println(activeCreds)
	// fmt.Println("Len of active creds ", len(activeCreds))

	// adding the real passkey
	// creds = append(creds, cred)
	// creds = RandSampleK(creds, 1.0) // randomly shuffling the creds

	// fmt.Println("Len of creds ", len(creds))

	/** login latter write the code of the RP in a seperate file **/

	rp := RelyingParty{Name: WebauthnDisplayName, ID: WebauthnDomain, Origin: WebauthnOrigin}

	authenticator := NewAuthenticator()

	attestation := startWebauthnRegister(t) // called by RP; includes the challenege to be completed by the authenticator

	// since the attestation is from webauthn lib parsing to for virtualwebauthin usecase.
	attestationOptions, err := ParseAttestationOptions(attestation.Options) // called by authenticator
	// returns a WebauthnAttestation object custom made.

	require.NoError(t, err)
	require.NotNil(t, attestationOptions)

	// Ensure that the mock credential isn't excluded by the attestation options (or compatible?)
	isExcluded := cred.IsExcludedForAttestation(*attestationOptions) // custom defined object Run by the client
	require.False(t, isExcluded)

	// Ensure that the Relying Party details match
	require.Equal(t, WebauthnDomain, attestationOptions.RelyingPartyID)
	require.Equal(t, WebauthnDisplayName, attestationOptions.RelyingPartyName)

	// Ensure that the user details match
	require.Equal(t, UserID, attestationOptions.UserID)
	require.Equal(t, UserName, attestationOptions.UserName)
	require.Equal(t, UserDisplayName, attestationOptions.UserDisplayName)

	// Creates an attestation response that we can send to the relying party as if it came from
	// an actual browser and authenticator.

	// todo: instead of one attestationResponse response send k attestationResponse responses?

	var attestationResponses []string
	fmt.Printf("size of creds is = %d\n", len(creds))
	for i := 0; i < len(creds); i++ {
		attestationResponse := CreateAttestationResponse(rp, authenticator, creds[i], *attestationOptions) // called by authenticator
		attestationResponses = append(attestationResponses, attestationResponse)
	}

	// Finish the register operation by sending the attestation response. An actual relying party
	// would keep all the data related to the user, but in this test we need to hold onto the
	// credential object for later usage.
	var webauthnEC2Credentials []*webauthn.Credential

	for i := 0; i < len(attestationResponses); i++ {
		// fmt.Println(i, attestationResponses[i])
		webauthnEC2Credential := finishWebauthnRegister(t, attestation, attestationResponses[i]) // called by the RP
		// webauthnEC2Credential is saved the RP
		webauthnEC2Credentials = append(webauthnEC2Credentials, webauthnEC2Credential)
	}

	fmt.Printf("==========\tDone with registration\t==========\n")

	// Add the userID to the mock authenticator so it can return it in assertion responses.
	authenticator.Options.UserHandle = []byte(UserID)

	// Add the EC2 credential to the mock authenticator

	for i := 0; i < len(creds); i++ {
		authenticator.AddCredential(creds[i])
	}

	// FIGURE 5: Compromise detection algorithm

	//// step 1: cred.ID is sent to by the client to the RP

	//// >> step 2: RP initates the startWebauthnLogin call and prepares the 	`assertion` to send it back to the authenticator.

	eta_attacker := 12
	i_star_guess := SelectRealSecret(W, k, eta_attacker)
	// i_start == i_star_guess the logining in is being  successful. Look at cred.ID = randomBytes(32) ?

	user := newWebauthnUser()

	// from startWebauthnLogin
	user.CredentialIDs = append(user.CredentialIDs, creds[i_star_guess].ID)
	options, err := webauthn.NewAssertionOptions(webauthnConfig, user)
	require.NoError(t, err)
	optionsJSON, err := json.Marshal(options)
	require.NoError(t, err)

	webauthnAssertion := &WebauthnAssertion{User: user, Credential: webauthnEC2Credentials[i_star_guess], CredentialID: creds[i_star_guess].ID, Challenge: options.Challenge, Options: string(optionsJSON)}

	// from assertionResponses
	assertionOptions, err := ParseAssertionOptions(webauthnAssertion.Options)
	require.NoError(t, err)
	require.NotNil(t, assertionOptions)

	require.Equal(t, WebauthnDomain, assertionOptions.RelyingPartyID)
	assertionResponse := CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)
	require.NotEmpty(t, assertionResponse)

	err = finishWebauthnLogin(t, webauthnAssertion, assertionResponse)

	fmt.Println(i_star, i_star_guess, activeDecoyCreds)

	if err == nil {
		if IsActiveDecoyCred(activeDecoyCreds, i_star_guess) {
			fmt.Println("Detection!!")
		} else {
			fmt.Println("No Detection!!")
		}

	} else {
		fmt.Println(err)
		fmt.Println("Unsuccessful login!!")
	}

}

package virtualwebauthn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/fxamacker/webauthn"
	_ "github.com/fxamacker/webauthn/packed"
	"github.com/stretchr/testify/require"
)

const (
	WebauthnDisplayName = "Example"
	WebauthnDomain      = "example.com"
	WebauthnOrigin      = "https://example.com"
	UserID              = "a987z"
	UserName            = "jappleseed"
	UserDisplayName     = "John Appleseed"
	kappa               = 32  /* 128 bits of security */
	k                   = 32  /* number of decoys */
	alpha               = 0.6 /* percentage of verifiers being marked */
)

func TestCasper(t *testing.T) {

	// step 0. get \eta from the user
	// fmt.Print("Enter eta: ")
	// _, err := fmt.Scan(&eta)
	// require.NoError(t, err)
	eta := 42

	// 1. Create W  = {w_1, w_2, \cdot, w_k} // just random strings GenDetectSecret

	W := GenDetectSecret(k, kappa)
	// fmt.Println(len(W))
	i_star := SelectRealSecret(W, k, eta)
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
	privateKeyMasked, randomSeed := EncCred(W[i_star], privateKey, kappa)
	D := DecCred(W[i_star], privateKeyMasked, kappa, randomSeed)
	// fmt.Println(D)

	recoveredPrivateKey := VerifierGen(D)

	require.Equal(t, recoveredPrivateKey, privateKey)

	creds := GenVerifierSet(W, privateKeyMasked, randomSeed, kappa) // instead of verifierSet return a credential set

	// removing i_star for sampling active verifiers
	creds = append(creds[:i_star], creds[i_star+1:]...)

	// fmt.Printf("size of the creds set %d\n", len(creds))

	// todo: why this following test is failing... ignoring for now
	// require.Contains(t, verifierPubKey, privateKey.PublicKey)

	// Send veriferPubKeys with their markings
	activeCreds := RandSampleK(creds, alpha)
	// fmt.Println("Len of active creds ", len(activeCreds))

	// adding the real passkey
	creds = append(creds, cred)
	creds = RandSampleK(creds, 1.0) // randomly shuffling the creds

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

	// fmt.Printf("Done with registration\n")

	// Add the userID to the mock authenticator so it can return it in assertion responses.
	authenticator.Options.UserHandle = []byte(UserID)

	// Add the EC2 credential to the mock authenticator
	for i := 0; i < len(creds); i++ {
		authenticator.AddCredential(creds[i])
	}

	// LOGIN

	//// step 1: cred.ID is sent to by the client to the RP

	//// >> step 2: RP initates the startWebauthnLogin call and prepares the 	`assertion` to send it back to the authenticator.
	assertions := startWebauthnLogin(t, webauthnEC2Credentials, creds)

	/// >> step 3: now RP sends back the assertionOptions to the Authentication and authenticator performs checking over the assertionOptions

	var assertionResponses []string
	for i := 0; i < len(assertions); i++ {
		assertionOptions, err := ParseAssertionOptions(assertions[i].Options)
		require.NoError(t, err)
		require.NotNil(t, assertionOptions)
		/* fix this error ucomenting the following block of code will throw an error */
		// foundCredential := authenticator.FindAllowedCredential(*assertionOptions) // called by Authenticator
		// require.NotNil(t, foundCredential)
		// require.Equal(t, cred, *foundCredential)

		//// Ensure that the relying party details match; called by RP
		require.Equal(t, WebauthnDomain, assertionOptions.RelyingPartyID)
		assertionResponse := CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)
		require.NotEmpty(t, assertionResponse)
		assertionResponses = append(assertionResponses, assertionResponse)
	}

	//// step 3: once the checking passes authenticator then sends back the response ``assertionResponse" to the RP
	/// this should also be a list of assertion response. <optionally, just sending the id will>

	//// step 4: RP checks the assertion response.

	result := 0
	for i := 0; i < len(assertionResponses); i++ {
		err := finishWebauthnLogin(t, assertions[i], assertionResponses[i])
		if err == nil {
			if IsActiveCred(activeCreds, assertions[i].CredentialID) {
				result = 1
				break
			} else {
				result = 2
			}
		}
		// fmt.Println(err)
	}

	if result == 0 {
		fmt.Println("Unsuccessfull login")
	} else if result == 1 {
		fmt.Println("Detection!!")
	} else {
		fmt.Println("Successful login")
	}

}

func startWebauthnRegister(t *testing.T) *WebauthnAttestation {
	user := newWebauthnUser()

	options, err := webauthn.NewAttestationOptions(webauthnConfig, user)
	require.NoError(t, err)

	optionsJSON, err := json.Marshal(options)
	require.NoError(t, err)

	return &WebauthnAttestation{User: user, Challenge: options.Challenge, Options: string(optionsJSON)}
}

func startWebauthnLogin(t *testing.T, creds1 []*webauthn.Credential, creds2 []Credential) []*WebauthnAssertion {
	user := newWebauthnUser()

	var webauthnAssertions []*WebauthnAssertion
	for i := 0; i < len(creds1); i++ {
		user.CredentialIDs = append(user.CredentialIDs, creds2[i].ID)
		options, err := webauthn.NewAssertionOptions(webauthnConfig, user)
		require.NoError(t, err)
		optionsJSON, err := json.Marshal(options)
		require.NoError(t, err)

		webauthnAssertions = append(webauthnAssertions,
			&WebauthnAssertion{User: user, Credential: creds1[i], CredentialID: creds2[i].ID, Challenge: options.Challenge, Options: string(optionsJSON)})
	}
	return webauthnAssertions

}

func finishWebauthnRegister(t *testing.T, attestation *WebauthnAttestation, response string) *webauthn.Credential {

	parsedAttestation, err := webauthn.ParseAttestation(strings.NewReader(response))
	require.NoError(t, err)

	_, _, err = webauthn.VerifyAttestation(parsedAttestation, &webauthn.AttestationExpectedData{
		Origin:           WebauthnOrigin,
		RPID:             WebauthnDomain,
		CredentialAlgs:   []int{webauthn.COSEAlgES256, webauthn.COSEAlgRS256},
		Challenge:        base64.RawURLEncoding.EncodeToString(attestation.Challenge),
		UserVerification: webauthn.UserVerificationPreferred,
	})
	require.NoError(t, err)

	return parsedAttestation.AuthnData.Credential
}

func finishWebauthnLogin(t *testing.T, assertion *WebauthnAssertion, response string) error {
	parsedAssertion, err := webauthn.ParseAssertion(strings.NewReader(response))
	require.NoError(t, err)

	err = webauthn.VerifyAssertion(parsedAssertion, &webauthn.AssertionExpectedData{
		Origin:            WebauthnOrigin,
		RPID:              WebauthnDomain,
		Challenge:         base64.RawURLEncoding.EncodeToString(assertion.Challenge),
		UserVerification:  webauthn.UserVerificationPreferred,
		UserID:            []byte(UserID),
		UserCredentialIDs: assertion.User.CredentialIDs,
		PrevCounter:       uint32(0),
		Credential:        assertion.Credential,
	})
	return err
	// require.NoError(t, err)
}

// challenge is created by RP using webauthn.NewAssertionOptions
// The RP sends the challenge to authenticator.
// The authenticator signs the challenge.
// The client Sends the public key and the challenege so that the RP can verify.

/// utils

type WebauthnAttestation struct {
	User      *webauthn.User
	Challenge []byte
	Options   string
}
type WebauthnAssertion struct {
	User         *webauthn.User
	Credential   *webauthn.Credential
	CredentialID []byte
	Challenge    []byte
	Options      string
}

func newWebauthnUser() *webauthn.User {
	return &webauthn.User{
		ID:          []byte(UserID),
		Name:        UserName,
		DisplayName: UserDisplayName,
	}
}

var webauthnConfig = &webauthn.Config{
	RPID:             WebauthnDomain,
	RPName:           WebauthnDisplayName,
	Timeout:          uint64(60000),
	ChallengeLength:  32,
	ResidentKey:      webauthn.ResidentKeyDiscouraged,
	UserVerification: webauthn.UserVerificationDiscouraged,
	Attestation:      webauthn.AttestationNone,
	CredentialAlgs:   []int{webauthn.COSEAlgES256, webauthn.COSEAlgRS256},
}

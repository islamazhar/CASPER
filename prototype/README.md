# CASPER 

This is a  prototype implementation of CASPER. The virtual authenticator and client are implemented  in GO based on the [virtualwebauthn](https://github.com/descope/virtualwebauthn) library. The relying party is simulated using the [webauthn server](https://github.com/fxamacker/webauthn) library.
    
# Requirements
- GO v1.23.1
- Python 3.8

# How to run 
To test the one time passkey backup and restoration protocol (BnR) run 
``` go 
go test -v -run TestCasper
```

# TODO
- [ ] Add the active decoy verifier
- [ ] separate the client and the RP code and put them over the network
- [ ] Run the model checking experiments
- [ ] Docker the whole thing
- [ ] publish the code
# CASPER 
CASPER, is a framework that enables websites to detect unauthorized login attempts using stolen passkeys. 
The name is a short for <ins>C</ins>apturing p<ins>AS</ins>skey com<ins>P</ins>romise by attack<ins>ER</ins>.
This repository  contains 1) prototype implementation of CASPER in GO, and 2) scripts of the detection effectiveness of CASPER run using [PRSIM](https://www.prismmodelchecker.org/) model checking tool. 

## Background
Synced passkeys are a user-friendly solution for account recovery where passkey management services (PMS) from Apple, Google, Microsoft back up users’ FIDO2 private signing keys to their cloud storage. This solution, however, exposes passkeys to the potential risk of PMS cloud storage compromise. Unfortunately, existing designs are unable to eliminate such a risk without reintroducing account recovery issues, leaving resulting abuse of leaked passkey difficult to detect. Therefore we propose a new detection framework, CASPER, which enables websites to detect unauthorized login attempts by making passkeys stolen from PMS identifiable.

## Results
 Our analysis shows that CASPER provides compelling detection effectiveness, even against attackers who may strategically optimize their attacks to evade CASPER’s detection by leveraging useful information obtained from data breaches that many web services experience today. We also show how to incorporate CASPER seamlessly into the existing passkey backup, synchronization, and authentication processes while introducing only minimal impact on user experience, negligible performance overhead, and minimum deployment and storage complexity for the participating parties
    
## Requirements
- GO v1.23.1
- Python 3.8


## How to run
- The folder `prototype` contains the the proof-of-concept implementation of CASPER in GO.
- The folder `detection-effectiveness` contains the scripts of our detection effectiveness run using PRSIM model checking tool. 

To run the prototype implementation type the following commands  
``` go
cd  prototype
go test -v -run TestCasper
```

## Acknowledgments
The virtual authenticator and client are implemented over the [virtualwebauthn](https://github.com/descope/virtualwebauthn) library. The relying party is simulated over the [webauthn server](https://github.com/fxamacker/webauthn) library.

# TODO
- [ ] Add the active decoy verifier
- [ ] separate the client and the RP code and put them over the network
- [ ] Run the model checking experiments
- [ ] Docker the whole thing
- [ ] publish the code

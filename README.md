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


## How to run?
### Prototype implementation
- The folder `prototype` contains the the proof-of-concept implementation of CASPER in GO.
- The folder `detection-effectiveness` contains the scripts of our detection effectiveness run using PRSIM model checking tool. 

To run the prototype implementation type the following commands  
``` bash
cd  prototype
go test -v -run TestCasperLogin
```
Similarly to test CASPER's detection capability use the  command `go test -v -run TestCasperDetection`.

[Note:] The current prototype does not run the RP, and PMS on dedicated nodes to measure the network latency. In the next version we will provide the necessary scripts to do this. 

### Detection effectiveness

To run the detection effectiveness  type the following commands  

``` bash
cd  detection-effectiveness
prism <name of the model file .prism> <corresponding property specification file .props>
```
For example to run minimum expected true detection probabilities (TDP) as a function of $\alpha$ with varying $m$ and $n$ (Figure 6 in the paper) run 

``` bash
cd  detection-effectiveness
prism passkey_tdp.prism passkey_tdp.props
```
Similarly for `eff` (Figure 8) with $\sigma=1$ and $\sigma=2$ use the `passkey_eff_std1.prism` and `passkey_eff_std1.prism` respectively. 

## Acknowledgments
The virtual authenticator and client are implemented over the [virtualwebauthn](https://github.com/descope/virtualwebauthn) library. The relying party is simulated over the [webauthn server](https://github.com/fxamacker/webauthn) library.

<!-- ## TODO
- [x] Add the active decoy verifier
- [ ] separate the BnR and CD protocols
- [ ] separate the client and the RP code and put them over the network
- [ ] Run the model checking experiments
- [ ] Docker the whole thing
- [ ] publish the code
- [ ] just saved the indexes of the activeCreds, and use index everywhere. Do not shuffle W. Even in detection use the indexs -->

<!-- Figure 6 passkey_tdp.prism passkey_tdp.propos-->
<!--- >  
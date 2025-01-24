# CASPER 

CASPER, is a framework that enables websites to detect unauthorized login attempts using stolen passkeys.  The name is a short for <ins>C</ins>apturing p<ins>AS</ins>skey com<ins>P</ins>romise by attack<ins>ER</ins>. This repository contains 1) the code of the prototype implementation we used for the   performance analysis of CASPER. 2) the model checking scripts (in <a href="https://www.prismmodelchecker.org/">PRSIM</a> model checking language) to evaluate the detection effectiveness of CASPER.


The paper is to appear at USENIX Security 2025. For details please refer to [our paper](https://pages.cs.wisc.edu/~mazharul/files/casperUsenix25Islam.pdf).

## Background
FIDO synced passkeys address account recovery challenges by enabling users to back up their FIDO2 private signing keys to the cloud storage of passkey management services (PMS). However, it introduces an additional risk — attackers can steal users’ passkeys through breaches of PMS’s cloud storage. Unfortunately, existing defenses cannot eliminate this risk without reintroducing account recovery challenges or disrupting users daily account login routines. 

## Results
We present CASPER, the first passkey breach detection framework that enables web service providers to detect the abuse of passkeys leaked from PMS for unauthorized login attempts. Our analysis shows that CASPER provides compelling detection effectiveness, even against knowledgeable attackers who strategically optimize their attacks to evade CASPER’s detection. We also show how CASPER can be seamlessly integrated into the existing passkey backup, synchronization, and authentication processes, with only minimal impact on user experience, negligible performance overhead, and minimum deployment and storage complexity for the participating parties.
    
## Requirements
- Go v1.23.1
- Python 3.8


## How to run?
### Prototype implementation
- The folder `prototype` contains the the proof-of-concept implementation of CASPER in Go.
- The folder `detection-effectiveness` contains the scripts of our detection effectiveness run using PRSIM model checking tool. 

To run the prototype implementation type the following commands  
``` bash
cd  prototype
go test -v -run TestCasperLogin
```
Similarly to test CASPER's detection capability use the  command `go test -v -run TestCasperDetection`.



### Detection effectiveness

To run the detection effectiveness experiments type the following commands  

``` bash
cd  detection-effectiveness
prism <name of the model file .prism> <corresponding property specification file .props>
```
For example to run the minimum expected true detection probabilities (TDP) as a function of $\alpha$ with varying $m$ and $n$ (Figure 6 in the paper) run 

``` bash
cd  detection-effectiveness
prism passkey_tdp.prism passkey_tdp.props
```
Similarly for the `eff` experiments (Figure 8 in the paper) with $\sigma=1$ and $\sigma=2$ use the `passkey_eff_std1.prism` and `passkey_eff_std2.prism` model files respectively. 

## Notes

- This repository is a proof-of-concept prototype. Please review it carefully before using it for any purposes.

- The current prototype does not run the RP and PMS on dedicated nodes to measure the network latency. In the next version we will provide the necessary scripts to do this. 
- We will also provide a docker image to run the experiments smoothly.  

## Acknowledgments
The virtual authenticator and client are implemented over the [virtualwebauthn](https://github.com/descope/virtualwebauthn) library. The relying party is simulated over the [webauthn server](https://github.com/fxamacker/webauthn) library.

## Contact
We are always looking for ways to improve our code. For any bugs please email at: mislam9@wisc.edu


## Citations

if you use any part of our code or paper please cite our paper.

```
@inproceedings{casper,
  title={{Detecting Compromise of Passkey Storage on the Cloud}},
  author={Mazharul Islam, Sunpreet S. Arora, Rahul Chatterjee, Ke Coby Wang},
  booktitle={34th {USENIX} Security Symposium ({USENIX} Security 25) (To appear)},
  year={2025},
  organization={USENIX}
}

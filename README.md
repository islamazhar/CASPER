# CASPER

## Background and Motivation
Synced passkeys --- although offers a user-friendly solution for account recovery --- are vulnerable to the potential risk of getting leaked when attacker compromised cloud storage
where they are stored. 
This repository contains a proof-of-concept implementation and detection 
effectiveness analysis scripts 
of a 
a new detection framework, we call CASPER, which enables websites to detect unauthorized login attempts by making passkeys stolen by attackers identifiable. 


## How to run
- The folder `prototype` contains the the proof-of-concept implementation of CASPER in GO. Please follow the readme file in the folder there.
- The folder `detection-effectiveness` contains the scripts of our detection effectiveness run using PRSIM model checking tool. 

## Todo

- [ ] Separate the code base for RP and client


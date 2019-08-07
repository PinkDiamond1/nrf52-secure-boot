### NRF52840 Cryptocell API - Side-Channel Attacks

This branch explores the possibilities of side-channel attacks against NRF52840's
Cryptocell implementation. The attacks listed in this branch were made using a
progressive methodology i.e. the master branch was updated with defense mechanisms
and was re-attacked to find another vulnerability.

*NOTE: This branch maintains the same file structure of the `master` branch*

#### Private Key Dump

* **Vulnerability:** The private key can be dumped from the SRAM memory section.
* **Folder:** sign_and_verify *(because it mocks the entire ECDSA algorithm)*
* **SDK Version:** 15.3.0
* **Required Hardware:** SWD Debugger

**What do we know about the vulnerability?**
NRF52840's cryptocell implementation provides different accelerators for crypto operations like SHA-2, Random Number Generation, Elliptic Curve Multiplication etc. although it **does not** provide **secure memory buffers** for storing private keys.

**How to reproduce the Private Key Dump and Extraction?**
Just go with the flow bro.

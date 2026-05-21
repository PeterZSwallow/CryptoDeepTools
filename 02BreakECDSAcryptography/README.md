# CryptoDeepTools
Crypto Deep Tools a set of scripts for detailed cryptanalysis of the Blockchain network in cryptocurrency Bitcoin 

---

## Analyze the data from the file "RawTX.json" (which we received in [01BlockchainGoogleDrive](https://github.com/demining/CryptoDeepTools/tree/main/01BlockchainGoogleDrive))


Script [breakECDSA.py](https://github.com/demining/CryptoDeepTools/blob/main/02BreakECDSAcryptography/breakECDSA.py) reconstructs the signed message for each to find the Z value. The result is returned as R, S, Z, PUBKEY for each of the inputs present in the data in the "RawTX.json" file.
## MAIN CHANGES 
Code works on Python 3.9 or newer.
All dependencies included in code. 

calculate.py  - count d (private key) if you have k-nonce R S Z. It's a trivial.
vulnerabilityR.py - 



---

## Commands:

pip install ecdsa
    




---
### All content will be saved in a file: "signatures.json"






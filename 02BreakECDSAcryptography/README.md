# CryptoDeepTools
Crypto Deep Tools a set of scripts for detailed cryptanalysis of the Blockchain network in cryptocurrency Bitcoin 

---

## Analyze the data from the file "RawTX.json" (which we received in [01BlockchainGoogleDrive](https://github.com/demining/CryptoDeepTools/tree/main/01BlockchainGoogleDrive))


Script [breakECDSA.py]([[https://github.com/PeterZSwallow/CryptoDeepTools/tree/main/02BreakECDSAcryptography/breakECDSA.py](https://github.com/PeterZSwallow/CryptoDeepTools/blob/main/02BreakECDSAcryptography/breakECDSA.py)]) reconstructs the signed message for each to find the Z value. The result is returned as R, S, Z, PUBKEY for each of the inputs present in the data in the "RawTX.json" file.
## MAIN CHANGES 
Code works on Python 3.9 or newer.
All dependencies included in code. 

calculate.py  - count d (private key) if you have k-nonce R S Z. It's a trivial.
Cryptographic Context: This script performs ECDSA private key recovery. In secure implementations, the nonce K must be cryptographically random and never reused or leaked. If K is known (as in this script), the private key can be trivially recovered.
Modular Arithmetic: All operations are performed modulo N, the order of the secp256k1 curve, ensuring results stay within the valid scalar field.
Safety: The code includes proper error handling for the modular inverse and correctly handles negative values in the extended GCD implementation.


vulnerabilityR.py - count d (private key) if you have same R in 2 different signatures. (Not low S and high S).
Mathematical Context: This script exploits a critical ECDSA implementation flaw: nonce reuse. Cryptographic standards strictly require the nonce k to be unpredictable and unique per signature. Reusing it leaks the private key.
Formula Breakdown: The one-liner (z1*s2 - z2*s1) * modinv(r*(s1-s2), p) % p directly solves for the private key d without needing to explicitly compute k first.
Python's Modulo: Python's % operator correctly handles negative intermediate values (e.g., s1 - s2), ensuring the final result stays within the valid [0, p-1] range.



---

## Commands:

pip install ecdsa
    




---
### All content will be saved in a file: "signatures.json"






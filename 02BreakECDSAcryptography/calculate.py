def h(n):
    """
    Convert an integer to a lowercase hexadecimal string.
    Removes the '0x' prefix commonly added by Python's hex() function.
    """
    return hex(n).replace("0x", "")

def extended_gcd(aa, bb):
    """
    Compute the Extended Euclidean Algorithm.
    Returns a tuple (gcd, x, y) such that: aa * x + bb * y = gcd(aa, bb)
    Handles negative inputs correctly by adjusting the signs of x and y at the end.
    """
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    
    while remainder:
        # Perform division: quotient = floor(lastremainder / remainder)
        # Update lastremainder and remainder simultaneously
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        # Update coefficients for the linear combination
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
        
    # Return gcd and coefficients, restoring original signs
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def modinv(a, m):
    """
    Calculate the modular multiplicative inverse of 'a' modulo 'm'.
    Finds 'x' such that (a * x) % m == 1.
    Raises ValueError if the inverse does not exist (i.e., when gcd(a, m) != 1).
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist (a and m are not coprime)")
    return x % m

# secp256k1 elliptic curve order (used in Bitcoin & Ethereum)
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# ECDSA signature components: r and s
R = 0x83fe1c06236449b69a7bee5be422c067d02c4ce3f4fa3756bd92c632f971de06
S = 0x7405249d2aa9184b688f5307006fddc3bd4a7eb89294e3be3438636384d64ce7

# Hash of the message that was signed (often called 'z')
Z = 0x070239c013e8f40c8c2a0e608ae15a6b1bb4b8fbcab3cff151a6e4e8e05e10b7

# Ephemeral nonce used during the signature generation (often called 'k')
K = 0x070239C013E8F40C8C2A0E608AE15A6B23D4A09295BE678B21A5F1DCEAE1F634

# ---------------------------------------------------------
# ECDSA Private Key Recovery Formula
# ---------------------------------------------------------
# In ECDSA, the signature equation is: s ≡ k⁻¹ * (z + d * r) (mod n)
# Rearranging to solve for the private key 'd':
#   k * s ≡ z + d * r (mod n)
#   d * r ≡ k * s - z (mod n)
#   d ≡ (k * s - z) * r⁻¹ (mod n)
# This script computes exactly that, recovering the private key when the nonce K is known.
# ---------------------------------------------------------

# Calculate the private key: d = ((S * K) - Z) * modinv(R, N) % N
private_key = ((S * K) - Z) * modinv(R, N) % N

# Output the recovered private key in raw hexadecimal format
print(h(private_key))

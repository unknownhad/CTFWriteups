"""
The RC4 (Rivest Cipher 4) algorithm is symmetric and uses the same key for both encryption and decryption. A key feature of RC4 is that identical plaintexts will yield identical ciphertexts if encrypted using the same key.
A critical property that your script is taking advantage of is that RC4 doesn't provide any IV (Initialization Vector) or any other form of randomness to each encryption. This means that the initial state of the RC4 keystream generator will be the same for both enc(flag) and enc(b'a'*36). It results in identical keystream being generated in each case for the same key.
This provides a weakness: if we have the keystream for one ciphertext, we can decrypt other ciphertexts encrypted with the same keystream. In your script, you're encrypting a known plaintext (b'a'*36) and an unknown plaintext (flag). This will allow us to get the keystream used for encryption and subsequently decrypt the flag.
The given ciphertexts are:
c0 = bytes.fromhex('b99665ef4329b168cc1d672dd51081b719e640286e1b0fb124403cb59ddb3cc74bda4fd85dfc')
c1 = bytes.fromhex('a5c237b6102db668ce467579c702d5af4bec7e7d4c0831e3707438a6a3c818d019d555fc')
We can XOR the known plaintext (b'a'*36) with c1 to get the keystream. Then we can XOR this keystream with c0 to get the flag.
"""

c0 = bytes.fromhex('b99665ef4329b168cc1d672dd51081b719e640286e1b0fb124403cb59ddb3cc74bda4fd85dfc')
c1 = bytes.fromhex('a5c237b6102db668ce467579c702d5af4bec7e7d4c0831e3707438a6a3c818d019d555fc')

# Calculate keystream from known plaintext
keystream = bytes([a ^ b for a, b in zip(c1, b'a'*36)])

# Decrypt unknown ciphertext using keystream
flag = bytes([a ^ b for a, b in zip(c0, keystream)])

# The flag has been reversed in the provided script
flag = flag[::-1]

print(flag)

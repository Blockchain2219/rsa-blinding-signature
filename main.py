import random
import math

def is_prime(n, k=5):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Miller-Rabin primality test
    def check_composite(a, s, d, n):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return False
        return True

    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        if check_composite(a, s, d, n):
            return False

    return True

def generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        # Ensure the number is odd
        candidate |= 1
        if is_prime(candidate):
            return candidate

def mod_inv(a, m):
    m0, x0, x1 = m, 0, 1

    while a > 1:
        q = a // m
        m, a = a % m, m

        x0, x1 = x1 - q * x0, x0

    if a == 1:
        return x1 % m0
    else:
        return None

def xor_co_prime_pairs_from_mid(number):
    mid = number // 2

    for num1 in range(mid, 1, -1):
        num2 = number - num1
        # Check if the GCD of the two numbers is 1
        if math.gcd(num1, num2) == 1:
            return num1, num2

    return None

def decrypt_and_compare(N, e, d, blind_factor, blind_message, unblinded_signature, message_bits):
    # Unblinding the Signature
    unblinded_signature = (unblinded_signature * mod_inv(blind_factor, N)) % N

    # Decryption using the private key
    decrypted_message = pow(unblinded_signature, d, N)

    # Filter the unnecessary bits from the decrypted message
    original_message = (blind_message * mod_inv(blind_factor, N)) % N

    # Extract the necessary bits from the original message
    extracted_decrypted_message = original_message & ((1 << message_bits) - 1)

    # Compare the extracted decrypted message with the input message
    if extracted_decrypted_message == m:
        return True, extracted_decrypted_message
    else:
        return False, extracted_decrypted_message
    
if __name__ == "__main__":
    # Key Generation
    p = generate_prime(1000)  # Generate a random 1000-bit prime
    q = generate_prime(1000)  # Generate another random 1000-bit prime
    phi_n = (p - 1) * (q - 1)  # Correctly calculate phi_n
    N = p * q
    k = 512  # k represents half the number of bits (e.g., 512 for 1024 bits)

    # Generate a random public exponent e (512 bits) with valid modular inverse
    min_e = 2**(k - 1) + 1
    max_e = phi_n - 1
    e = None
    d = None

    while e is None or e == phi_n or d is None:
        e = random.randint(min_e, max_e)
        if math.gcd(e, phi_n) == 1:
            d = mod_inv(e, phi_n)
            if d is not None:
                break

    if e is None or d is None:
        print("Error: Could not find a suitable public exponent and modular inverse.")
        exit()

    print("Public key pair (e, N):", (e, N))
    print("Private key pair (d, N):", (d, N))

    # Find one blind factor from the mid of N
    num1, num2 = xor_co_prime_pairs_from_mid(N)
    if num1 is None or num2 is None:
        print("Error: Could not find co-prime pairs.")
        exit()

    # Generate a random message and calculate the required message bits
    m = int(input("Enter the message: "))
    if m < 0:
        print("Invalid message. The message should be between 0 and 1023.")
        exit()

    message_bits = math.ceil(math.log2(m + 1))
    print("Message Bits:", message_bits)

    # Calculate the blind message
    blind_factor = mod_inv(num1, N)
    blind_message = (blind_factor * m) % N
    print("Blind message:", blind_message)

    # Sign Generation
    rec = blind_message
    Sg = pow(rec, d, N)

    # Unblinding the Signature
    unblinded_signature = (Sg * num2) % N

    # Signature Verification
    verified, decrypted_message = decrypt_and_compare(N, e, d, blind_factor, blind_message, unblinded_signature, message_bits)

    if verified:
        print("The Signer is Authenticated. Decrypted Message:", decrypted_message)
        truncated_decrypted_message = decrypted_message & ((1 << message_bits) - 1)
        print("Truncated Decrypted Message ({}-bit):".format(message_bits), truncated_decrypted_message)
    else:
        print("The Signer is not Authenticated.")
        truncated_decrypted_message = decrypted_message & ((1 << message_bits) - 1)
        print("Truncated Decrypted Message ({}-bit):".format(message_bits), truncated_decrypted_message)
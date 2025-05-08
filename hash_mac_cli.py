#!/usr/bin/env python3
import hashlib
import hmac
import os
import sys
import getpass

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_header():
    print("\n========== HASH & MAC DEMONSTRATION TOOL ==========\n")

def print_menu():
    print("Menu Options:")
    print("1. Generate SHA-256 Hash")
    print("2. Generate HMAC-SHA256 (MAC)")
    print("3. Verify HMAC-SHA256")
    print("4. Show Information")
    print("5. Exit")
    print("\nEnter your choice (1-5): ", end="")

def generate_hash():
    clear_screen()
    print_header()
    print("===== SHA-256 Hash Generator =====\n")
    
    print("Enter the text to hash (press Enter twice to finish):")
    lines = []
    while True:
        line = input()
        if not line and lines:
            break
        lines.append(line)
    
    if not lines:
        print("\nNo input provided.")
        return
        
    input_text = "\n".join(lines).encode('utf-8')
    hash_result = hashlib.sha256(input_text).hexdigest()
    
    print("\nSHA-256 Hash Result:")
    print(hash_result)
    
    input("\nPress Enter to return to the main menu...")

def generate_mac():
    clear_screen()
    print_header()
    print("===== HMAC-SHA256 Generator =====\n")
    
    print("Enter the text to create MAC (press Enter twice to finish):")
    lines = []
    while True:
        line = input()
        if not line and lines:
            break
        lines.append(line)
    
    if not lines:
        print("\nNo input provided.")
        return
        
    input_text = "\n".join(lines).encode('utf-8')
    
    key_option = input("\nChoose key option:\n1. Enter your own key\n2. Generate random key\nYour choice (1-2): ")
    
    if key_option == "1":
        key = getpass.getpass("Enter your secret key: ")
        if not key:
            print("No key provided. Returning to main menu...")
            return
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = os.urandom(32)
        key_hex = key_bytes.hex()
        print(f"\nGenerated random key (save this for verification):\n{key_hex}")
    
    mac_result = hmac.new(key_bytes, input_text, hashlib.sha256).hexdigest()
    
    print("\nHMAC-SHA256 Result:")
    print(mac_result)
    
    input("\nPress Enter to return to the main menu...")

def verify_mac():
    clear_screen()
    print_header()
    print("===== HMAC-SHA256 Verification =====\n")
    
    print("Enter the original text (press Enter twice to finish):")
    lines = []
    while True:
        line = input()
        if not line and lines:
            break
        lines.append(line)
    
    if not lines:
        print("\nNo input provided.")
        return
        
    input_text = "\n".join(lines).encode('utf-8')
    
    key_input = getpass.getpass("\nEnter the secret key: ")
    if not key_input:
        print("No key provided. Returning to main menu...")
        return
    
    # Check if key is a hex string (from random generation)
    try:
        if len(key_input) == 64 and all(c in '0123456789abcdefABCDEF' for c in key_input):
            key_bytes = bytes.fromhex(key_input)
        else:
            key_bytes = key_input.encode('utf-8')
    except ValueError:
        key_bytes = key_input.encode('utf-8')
    
    mac_to_verify = input("\nEnter the MAC to verify: ")
    if not mac_to_verify:
        print("No MAC provided. Returning to main menu...")
        return
    
    calculated_mac = hmac.new(key_bytes, input_text, hashlib.sha256).hexdigest()
    
    print("\nVerification Result:")
    if hmac.compare_digest(calculated_mac, mac_to_verify):
        print("✓ MAC is VALID! The message integrity is confirmed.")
    else:
        print("✗ MAC is INVALID! The message may have been tampered with.")
    
    input("\nPress Enter to return to the main menu...")

def show_info():
    clear_screen()
    print_header()
    print("===== Information about Hash & MAC =====\n")
    
    info_text = """
SHA-256 (Secure Hash Algorithm 256-bit)
---------------------------------------
- Part of the SHA-2 family of cryptographic hash functions
- Produces a 256-bit (32-byte) hash value, typically rendered as 64 hexadecimal characters
- Used widely in security applications and protocols, including TLS, SSL, SSH, PGP, and blockchain technologies
- Properties: one-way function (can't be reversed), deterministic, collision-resistant

HMAC-SHA256
-----------
- Hash-based Message Authentication Code using SHA-256
- Combines a cryptographic hash function (SHA-256) with a secret key
- Purpose: verify both the data integrity and authenticity of a message
- Formula: HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
  where K is the key, m is the message, H is the hash function, and ⊕ is XOR

Common Applications
------------------
- Password storage (hash only, not MAC)
- Digital signatures
- Data integrity verification
- API authentication
- Secure communication protocols
- Blockchain and cryptocurrency transactions

Developed by: Đỗ Thế Sang
"""
    print(info_text)
    
    input("\nPress Enter to return to the main menu...")

def main():
    while True:
        clear_screen()
        print_header()
        print_menu()
        
        try:
            choice = input()
        except EOFError:
            print("\nExiting program...")
            sys.exit(0)
            
        if choice == "1":
            generate_hash()
        elif choice == "2":
            generate_mac()
        elif choice == "3":
            verify_mac()
        elif choice == "4":
            show_info()
        elif choice == "5":
            print("\nThank you for using the Hash & MAC Demonstration Tool!")
            sys.exit(0)
        else:
            print("\nInvalid choice. Press Enter to try again...")
            input()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram terminated by user. Goodbye!")
        sys.exit(0)
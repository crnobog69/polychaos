import os
import hmac
import hashlib

class EnhancedPoliChaosCipher:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.key[i % len(self.key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def generate_keystream(self, length):
        i = j = 0
        keystream = []
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            K = self.S[(self.S[i] + self.S[j]) % 256]
            keystream.append(K)
        return keystream

    def xor_bytes(self, data, keystream):
        return bytes([a ^ b for a, b in zip(data, keystream)])

    def polybius_square_encode(self, text):
        square = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        encoded = ""
        for char in text.upper():
            if char in square:
                row = square.index(char) // 6 + 1
                col = square.index(char) % 6 + 1
                encoded += f"{row}{col}"
            else:
                encoded += char
        return encoded

    def polybius_square_decode(self, text):
        square = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        decoded = ""
        i = 0
        while i < len(text):
            if text[i].isdigit() and i+1 < len(text) and text[i+1].isdigit():
                row = int(text[i]) - 1
                col = int(text[i+1]) - 1
                index = row * 6 + col
                if index < len(square):
                    decoded += square[index]
                i += 2
            else:
                decoded += text[i]
                i += 1
        return decoded

    def encrypt(self, plaintext):
        polybius_text = self.polybius_square_encode(plaintext)
        data = polybius_text.encode()
        iv = os.urandom(16)  # Generisanje slučajnog IV-a
        keystream = self.generate_keystream(len(data) + len(iv))
        encrypted = self.xor_bytes(iv + data, keystream)
        hmac_key = self.key  # Koristi isti ključ za HMAC, može biti različit
        mac = hmac.new(hmac_key, encrypted, hashlib.sha256).digest()
        return (encrypted + mac).hex()

    def decrypt(self, ciphertext):
        data = bytes.fromhex(ciphertext)
        mac = data[-32:]
        encrypted = data[:-32]
        hmac_key = self.key
        if not hmac.compare_digest(mac, hmac.new(hmac_key, encrypted, hashlib.sha256).digest()):
            raise ValueError("Podaci su kompromitovani ili ključ nije ispravan")
        iv = encrypted[:16]
        data = encrypted[16:]
        keystream = self.generate_keystream(len(data) + len(iv))
        decrypted = self.xor_bytes(iv + data, keystream)[16:]
        polybius_text = decrypted.decode()
        return self.polybius_square_decode(polybius_text)

def main():
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

    key = input(f"{CYAN}Unesite ključ: {RESET}")
    cipher = EnhancedPoliChaosCipher(key)

    while True:
        print(f"{YELLOW}\n--- PoliChaos Cipher ---{RESET}")
        choice = input(f"{GREEN}Izaberite opciju (E za šifrovanje, D za dešifrovanje, Q za izlaz): {RESET}").upper()
        if choice == 'E':
            message = input(f"{CYAN}Unesite poruku za šifrovanje: {RESET}")
            encrypted = cipher.encrypt(message)
            print(f"{MAGENTA}Šifrovana poruka: {encrypted}{RESET}")
        elif choice == 'D':
            ciphertext = input(f"{CYAN}Unesite šifrovanu poruku za dešifrovanje: {RESET}")
            try:
                decrypted = cipher.decrypt(ciphertext)
                print(f"{MAGENTA}Dešifrovana poruka: {decrypted}{RESET}")
            except ValueError as e:
                print(f"{RED}{e}{RESET}")
        elif choice == 'Q':
            print(f"{RED}Izlaz iz programa.{RESET}")
            break
        else:
            print(f"{RED}Nepoznata opcija!{RESET}")

if __name__ == "__main__":
    main()

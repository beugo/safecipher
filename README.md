# SafeCipher; Classical Ciphers with a Focus on Secure Coding

## Project Overview
This project implements encryption and decryption functions for both the Caesar and Vigenère ciphers as part of UWA's CITS3007 course. It includes a command-line interface (CLI) to allow users to perform encryption and decryption tasks via terminal commands. The code incorporates secure coding practices such as input validation, memory safety, and error handling to ensure reliability and minimise security risks.

---

## Features
- **Caesar Cipher**: Encrypt and decrypt messages using a simple substitution cipher.
- **Vigenère Cipher**: Encrypt and decrypt messages using a more secure polyalphabetic cipher.
- **Command-Line Interface**: A CLI to easily interact with the implemented encryption and decryption functions.

---

## How to Compile
To compile the project, use the provided `Makefile`:
```bash
make
```
This will generate an executable named `safecipher`.

---

## How to Run
The CLI supports the following operations:
- **Caesar Cipher**
  - `caesar-encrypt`
  - `caesar-decrypt`
- **Vigenère Cipher**
  - `vigenere-encrypt`
  - `vigenere-decrypt`

### Usage
```bash
./project <operation> <key> <message>
```
### Example
Encrypt a message using the Caesar cipher:
```bash
./project caesar-encrypt 3 HELLO
```
Decrypt a message using the Vigenère cipher:
```bash
./project vigenere-decrypt KEY RIJVSUYVJN
```

### Input Validation
- **Caesar Cipher Key**: Must be an integer value.
- **Vigenère Cipher Key**: Must consist of uppercase letters in the range 'A' to 'Z'.

---

## Functions
### Caesar Cipher
- **`caesar_encrypt`**: Encrypts a plaintext message using a given key.
- **`caesar_decrypt`**: Decrypts a ciphertext message using a given key.

### Vigenère Cipher
- **`vigenere_encrypt`**: Encrypts a plaintext message using a keyword.
- **`vigenere_decrypt`**: Decrypts a ciphertext message using a keyword.

### Command-Line Interface
- **`cli`**: Handles user input and calls the appropriate encryption or decryption functions.

---

## Security Considerations
The project follows secure coding best practices:
- Proper input validation.
- Avoidance of buffer overflows.
- Clear error handling.
- Modular design to enhance maintainability and reduce security risks.
- Avoidance of dangerous functions (like gets() or atoi())



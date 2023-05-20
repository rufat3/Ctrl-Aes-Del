# AES Encryption and Decryption

This Java program demonstrates AES encryption and decryption using different modes of operation, including ECB (Electronic Codebook), CBC (Cipher Block Chaining), and CTR (Counter). AES (Advanced Encryption Standard) is a symmetric encryption algorithm widely used for secure data transmission and storage.

The program allows the user to choose between encrypting a plaintext or decrypting a cipher. When encrypting, the user can either generate an encryption key or enter an existing encryption key. The plaintext is then encrypted using the selected encryption mode. When decrypting, the user is prompted to enter the encryption key and the cipher (base64 encoded). The program decrypts the cipher using the selected decryption mode and returns the decrypted text.

## Features

- Generate a random encryption key or enter an existing encryption key.
- Encrypt plaintext using AES with ECB, CBC, or CTR mode.
- Decrypt a cipher using AES with ECB, CBC, or CTR mode.
- Input and output are handled through the command line interface.

## Prerequisites

- Java Development Kit (JDK) installed on your machine.

## Usage

1. Clone this repository or download the source code.
2. Open a terminal or command prompt and navigate to the project directory.
3. Compile the Java source file using the following command:

   ```shell
   javac AES.java
   
4. Run the program using the following command:

 ```shell
   java AES


   

#include "crypto.h"

#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#define   RANGE_LOW   'A'
#define   RANGE_HIGH  'Z'



// returns true if a string contains any whitespace
bool contains_whitespace(const char *str) {
    while (*str) {
        if (isspace((unsigned char)*str)) {
            return true;
        }
        str++;
    }
    return false;
}

// returns true if characters in a string are within the set range
bool validate_key_characters(const char *str) {
    while (*str) {
        if (*str < RANGE_LOW || *str > RANGE_HIGH) {
            return false;
        }
        str++;
    }
    return true;
}

// handles case where a vigenere encryption/decryption is required
// validates that all characters in key are within range
// calls the vigenere encrypt/decrypt function as needed
// prints the resulting text
int handle_vigenere(const char *operation, const char *key_str, const char *message, char *result_text) {
    // rejects any key with characters out of the range 'A'->'Z'
    if (!validate_key_characters(key_str)) {
        fprintf(stderr, "Key characters must be in the range 'A'->'Z'\n");
        return 1;
    }

    if (strcmp(operation, "vigenere-encrypt") == 0) {
        vigenere_encrypt(RANGE_LOW, RANGE_HIGH, key_str, message, result_text);
    } else {
        vigenere_decrypt(RANGE_LOW, RANGE_HIGH, key_str, message, result_text);
    }

    printf("%s\n", result_text);

    return 0;
}

// handles case where a caesar encryption/decryption is required
// validates that key is an appropriate integer
// calls the caesar encrypt/decrypt function as needed
// prints the resulting text
int handle_caesar(const char *operation, const char *key_str, const char *message, char *result_text) {
    
    char *endptr;
    long int key_int = strtol(key_str, &endptr, 10);

    // rejects a key if it:
    // - contains any non-digit characters or whitespace
    // - would cause an integer overflow
    if (*endptr != '\0' || contains_whitespace(key_str) ||
       key_int < INT_MIN || INT_MAX < key_int) {
        fprintf(stderr, "Please enter a valid integer key\n");
        return 1;
    }

    // wrap key to acceptable range
    int range_size = RANGE_HIGH - RANGE_LOW + 1;
    key_int = (key_int % range_size + range_size) % range_size;

    if (strcmp(operation, "caesar-encrypt") == 0) {
        caesar_encrypt(RANGE_LOW, RANGE_HIGH, (int)key_int, message, result_text);
    } else {
        caesar_decrypt(RANGE_LOW, RANGE_HIGH, (int)key_int, message, result_text);
    }

    printf("%s\n", result_text);

    return 0;
}

// prints instructions for using program
void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s <operation> <key> <message>\n", program_name);
    fprintf(stderr, "Permitted operations: vigenere-encrypt, vigenere-decrypt, caesar-encrypt, caesar-decrypt\n");
}

/** This function handles various encryption and decryption operations based on user input. It requires specific 
  * command-line arguments and includes validation to ensure correct usage.
  *
  * Supported operations:
  * - vigenere-encrypt: Encrypts the given message using \ref vigenere_encrypt with the provided key.
  * - vigenere-decrypt: Decrypts the given message using \ref vigenere_decrypt with the provided key.
  * - caesar-encrypt: Encrypts the given message using \ref caesar_encrypt with the provided key.
  * - caesar-decrypt: Decrypts the given message using \ref caesar_decrypt with the provided key.
  *
  * The function executes the following steps:
  * - Validates the number of arguments.
  * - Extracts the operation, key, and message from the arguments.
  * - Validates the key and operation.
  * - Executes the appropriate encryption or decryption function based on the operation.
  *
  * \param argc The number of command-line arguments.
  * \param argv An array of strings representing the command-line arguments.
  *             - argv[0]: The name of the program.
  *             - argv[1]: The operation to perform (e.g., "vigenere-encrypt").
  *             - argv[2]: The key for the encryption/decryption.
  *             - argv[3]: The message to be encrypted or decrypted.
  * \return An integer status code.
  *         - Returns 0 upon successful execution of the specified operation.
  *         - Returns 1 and prints to stderr on error (e.g., invalid usage, invalid operation, invalid key).
  *
  * \pre `argc` must be 4.
  * \pre `argv` must be a valid array of strings.
  * \pre `argv[1]` must be one of the supported operations.
  * \pre `argv[2]` must be a valid key string for Vigenere operations, or a valid integer for Caesar operations.
  *     - A valid key string must consist of characters in the range 'A' to 'Z'.
  *     - A valid integer must contain no whitespace, only digit characters, and be within the range INT_MIN to INT_MAX.
  * \pre `argv[3]` must be a valid null-terminated C string representing the message.
  *
  * \post The specified operation is performed and the result is output to the standard output.
  */

int cli(int argc, char **argv) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char *operation = argv[1];
    const char *key_str = argv[2];
    const char *message = argv[3];

    // ensure that a key and message was provided
    if (key_str[0] == '\0' || message[0] == '\0') {
        print_usage(argv[0]);
        return 1;
    }

    // check that message length does not exceed buffer 
    if (strlen(message) >= 1024) {
        fprintf(stderr, "Error: Message length exceeds maximum allowed size of 1023 characters\n");
        return 1;
    }
    
    // allocate buffer for the result text
    char result_text[1024] = {0};

    int flag = 0;

    if (strcmp(operation, "vigenere-encrypt") == 0 || strcmp(operation, "vigenere-decrypt") == 0) {
        flag = handle_vigenere(operation, key_str, message, result_text);
    } else if (strcmp(operation, "caesar-encrypt") == 0 || strcmp(operation, "caesar-decrypt") == 0) {
        flag = handle_caesar(operation, key_str, message, result_text);
    } else {
        fprintf(stderr, "Invalid operation: %s\n", operation);
        print_usage(argv[0]);
        return 1;
    }

    return flag;
}


// caesar cipher encryption
void caesar_encrypt(char range_low, char range_high, int key, const char * plain_text, char * cipher_text)
{
    size_t plain_text_len = strlen(plain_text);
    int range_size = range_high - range_low + 1;
    key = (key % range_size + range_size) % range_size;

    for (size_t i = 0; i < plain_text_len; i++) {
        char c = plain_text[i];
        if (range_low <= c && c <= range_high) {
            c = (char)(range_low + abs((c - range_low + key) % range_size));
        }
        cipher_text[i] = c;
    }
    cipher_text[plain_text_len] = '\0';
}

// caesar cipher decryption
void caesar_decrypt(char range_low, char range_high, int key, const char * cipher_text, char * plain_text)
{
    caesar_encrypt(range_low, range_high, -key, cipher_text, plain_text);
}

// vigenere cipher encryption
void vigenere_encrypt(char range_low, char range_high, const char *key,
                      const char *plain_text, char *cipher_text) {
    size_t plain_text_len = strlen(plain_text);
    size_t key_length = strlen(key);
    size_t index = 0;

    for (size_t i = 0; i < plain_text_len; i++) {
        char c = plain_text[i];

        if (range_low <= c && c <= range_high) {
            int caesar_key = key[index] - range_low;
            caesar_encrypt(range_low, range_high, caesar_key, &plain_text[i], &cipher_text[i]);
            index = (index + 1) % key_length;
        } else {
            cipher_text[i] = c;
        }
    }
    cipher_text[plain_text_len] = '\0';
}

// vigenere cipher decryption
void vigenere_decrypt(char range_low, char range_high, const char *key,
                      const char *cipher_text, char *plain_text) {
    size_t cipher_text_len = strlen(cipher_text);
    size_t key_length = strlen(key);
    size_t index = 0;

    for (size_t i = 0; i < cipher_text_len; i++) {
        char c = cipher_text[i];
        if (range_low <= c && c <= range_high) {
            int caesar_key = key[index] - range_low;
            caesar_decrypt(range_low, range_high, caesar_key, &cipher_text[i], &plain_text[i]);
            index = (index + 1) % key_length;
        } else {
            plain_text[i] = c;
        }
    }
    plain_text[cipher_text_len] = '\0';
}





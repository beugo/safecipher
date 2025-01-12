#include "crypto.h"

#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#define   RANGE_LOW   'A'
#define   RANGE_HIGH  'Z'



// checks if a string contains any whitespace
bool containsWhitespace(const char *str) {
    while (*str) {
        if (isspace((unsigned char)*str)) {
            return true;
        }
        str++;
    }
    return false;
}

// checks that characters in a string are within the required range
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
int handle_vigenere(const char *operation, const char *key_str, const char *message) {
    // rejects any key with characters out of the range 'A'->'Z'
    if (!validate_key_characters(key_str)) {
        fprintf(stderr, "Key characters must be in the range 'A'->'Z'\n");
        return 1;
    }

    char result_text[strlen(message) + 1];

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
int handle_caesar(const char *operation, const char *key_str, const char *message) {
    char *endptr;
    long int num = strtol(key_str, &endptr, 10);

    // rejects a key if it:
    // contains any non-digit characters or whitespace
    // would cause an integer overflow
    if (*endptr != '\0' || num < INT_MIN || num > INT_MAX || containsWhitespace(key_str)) {
        fprintf(stderr, "Please enter a valid integer\n");
        return 1;
    }

    // allows key to wrap if it is outside required range
    int key_int = ((int)num) % (RANGE_HIGH - RANGE_LOW + 1);

    char result_text[strlen(message) + 1];

    if (strcmp(operation, "caesar-encrypt") == 0) {
        caesar_encrypt(RANGE_LOW, RANGE_HIGH, key_int, message, result_text);
    } else {
        caesar_decrypt(RANGE_LOW, RANGE_HIGH, key_int, message, result_text);
    }

    printf("%s\n", result_text);

    return 0;
}

// prints instructions for using program
void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s <operation> <key> <message>\n", prog_name);
    fprintf(stderr, "Valid operations: vigenere-encrypt, vigenere-decrypt, caesar-encrypt, caesar-decrypt\n");
}

/** This function handles various encryption and decryption operations based on user input. The function expects 
  * specific command-line arguments and performs validation to ensure correct usage.
  *
  * The supported operations are:
  * - vigenere-encrypt: Encrypts the given message using \ref vigenere_encrypt with the specified key.
  * - vigenere-decrypt: Decrypts the given message using \ref vigenere_decrypt with the specified key.
  * - caesar-encrypt: Encrypts the given message using \ref caesar_encrypt with the specified key.
  * - caesar-decrypt: Decrypts the given message using \ref  caesar_decrypt with the specified key.
  *
  * The function performs the following steps:
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
  *         - Returns 0 on successful execution of the specified operation.
  *         - Returns 1 on error (e.g., invalid usage, invalid operation, invalid key).
  *
  * \pre `argc` must be 4.
  * \pre `argv` must be a valid array of strings.
  * \pre `argv[1]` must be one of the supported operations.
  * \pre `argv[2]` must be a valid key string for Vigenere operations, or a valid integer for Caesar operations.
  * \pre `argv[3]` must be a valid null-terminated C string representing the message.
  *
  * \post The specified operation is performed and the result is printed to the standard output.
  */
int main(int argc, char **argv) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char *operation = argv[1];
    const char *key_str = argv[2];
    const char *message = argv[3];

    // ensure that a key was provided
    if (key_str[0] == '\0') {
        fprintf(stderr, "Must provide key\n");
        return 1;
    }

    int flag = 0;

    if (strcmp(operation, "vigenere-encrypt") == 0 || strcmp(operation, "vigenere-decrypt") == 0) {
        flag = handle_vigenere(operation, key_str, message);
    } else if (strcmp(operation, "caesar-encrypt") == 0 || strcmp(operation, "caesar-decrypt") == 0) {
        flag = handle_caesar(operation, key_str, message);
    } else {
        fprintf(stderr, "Invalid operation: %s\n", operation);
        print_usage(argv[0]);
        return 1;
    }

    return flag;
}

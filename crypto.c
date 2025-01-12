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





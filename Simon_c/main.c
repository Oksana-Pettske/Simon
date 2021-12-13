#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <memory.h>
#include <malloc.h>
#include "simon.h"

#define rshift_three(x) (x >> 3) | ((x & 0x7) << (word_size - 3))
#define rshift_one(x) (x >> 1) | ((x & 0x1) << (word_size - 1))
#define shift_one ((x_word << 1) | (x_word >> (word_size - 1)))
#define shift_eight ((x_word << 8) | (x_word >> (word_size - 8)))
#define shift_two ((x_word << 2) | (x_word >> (word_size - 2)))

const uint8_t block_sizes[] = { 32, 48, 64, 96, 128 };
const uint16_t key_sizes[] = { 64, 96, 128, 144, 256 };
const uint8_t round_limits[] = { 32, 36, 44, 54, 72 };
const uint8_t z_assign[] = { 0, 1, 2, 3, 4 };

uint64_t z_arrays[5] = {0b0001100111000011010100100010111110110011100001101010010001011111,
                        0b0001011010000110010011111011100010101101000011001001111101110001,
                        0b0011001101101001111110001000010100011001001011000000111011110101,
                        0b0011110000101100111001010001001000000111101001100011010111011011,
                        0b0011110111001001010011000011101000000100011011010110011110001011};

uint8_t simon_init(simon_cipher *cipher, enum config_t simon_config, void *key) {
    uint8_t word_size, word_bytes, key_words;
    uint64_t mod_mask, tmp_1, tmp_2;
    uint64_t c = 0xFFFFFFFFFFFFFFFC;
    uint64_t sub_keys[4] = {};
    int i, j;

    if (simon_config > simon_256_128 || simon_config < simon_64_32) {
        return -1;
    }

    cipher->simon_config = simon_config;
    cipher->block_size = block_sizes[simon_config];
    cipher->key_size = key_sizes[simon_config];
    cipher->round_limit = round_limits[simon_config];
    cipher->z_seq = z_assign[simon_config];

    word_size = block_sizes[simon_config] >> 1;
    word_bytes = word_size >> 3;
    key_words = key_sizes[simon_config] / word_size;
    mod_mask = ULLONG_MAX >> (64 - word_size);

    for (i = 0; i < key_words; i++) {
        memcpy(&sub_keys[i], key + (word_bytes * i), word_bytes);
    }

    memcpy(cipher->key_sched, &sub_keys[0], word_bytes);

    for (i = 0; i < round_limits[simon_config] - 1; i++) {
        tmp_1 = rshift_three(sub_keys[key_words -1]);

        if (key_words == 4) {
            tmp_1 ^= sub_keys[1];
        }

        tmp_2 = rshift_one(tmp_1);
        tmp_1 ^= sub_keys[0];
        tmp_1 ^= tmp_2;

        tmp_2 = c ^ ((z_arrays[cipher->z_seq] >> (i % 62)) & 1);

        tmp_1 ^= tmp_2;

        for (j = 0; j < (key_words - 1); j++) {
            sub_keys[j] = sub_keys[j + 1];
        }

        sub_keys[key_words - 1] = tmp_1 & mod_mask;

        memcpy(cipher->key_sched + (word_bytes * (i + 1)), &sub_keys[0], word_bytes);
    }

    return 0;
}

uint8_t simon_encrypt(simon_cipher cipher, void *plain_text, void *cipher_text) {
    if (cipher.simon_config == simon_64_32) {
        simon_encrypt_32(cipher.key_sched, plain_text, cipher_text);
    }
    else if (cipher.simon_config <= simon_96_48) {
        simon_encrypt_48(cipher.round_limit, cipher.key_sched, plain_text, cipher_text);
    }
    else if(cipher.simon_config <= simon_128_64) {
        simon_encrypt_64(cipher.round_limit, cipher.key_sched, plain_text, cipher_text);
    }
    else if(cipher.simon_config <= simon_144_96) {
        simon_encrypt_96(cipher.round_limit, cipher.key_sched, plain_text, cipher_text);
    }
    else if(cipher.simon_config <= simon_256_128) {
        simon_encrypt_128(cipher.round_limit, cipher.key_sched, plain_text, cipher_text);
    }
    else return -1;

    return 0;
}

void simon_encrypt_32(uint8_t *key_sched, uint8_t *plain_text, uint8_t *cipher_text) {
    const uint8_t word_size = 16;
    uint16_t y_word = *(uint16_t *)plain_text;
    uint16_t x_word = *(((uint16_t *)plain_text) + 1);
    uint16_t *round_key_ptr = (uint16_t *)key_sched;
    uint16_t *word_ptr = (uint16_t *)cipher_text;
    uint16_t tmp;
    uint8_t i;

    for (i = 0; i < 32; i++) {
        tmp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        y_word = x_word;

        x_word = tmp ^ *(round_key_ptr + i);
    }

    *word_ptr = y_word;
    *(word_ptr + 1) = x_word;
}

void simon_encrypt_48(uint8_t round_limit, uint8_t *key_sched, uint8_t *plain_text, uint8_t *cipher_text) {
    const uint8_t word_size = 24;

    bword_24 bw = *(bword_24 *)plain_text;
    uint32_t y_word = bw.data;

    bw = *((bword_24 *)(plain_text + 3));
    uint32_t x_word = bw.data;

    bword_24 *bw_ptr = (bword_24 *)cipher_text;

    uint32_t tmp;
    uint8_t i;

    for (i = 0; i < round_limit; i++) {
        tmp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        y_word = x_word;

        x_word = (tmp ^ (*((bword_24 *)(key_sched + (i * 3)))).data) & 0xFFFFFF;
    }

    bw.data = y_word;
    *bw_ptr = bw;

    bw.data = x_word;
    bw_ptr = (bword_24 *)(cipher_text + 3);
    *bw_ptr = bw;
}

void simon_encrypt_64(uint8_t round_limit, uint8_t *key_sched, uint8_t *plain_text, uint8_t *cipher_text) {
    const uint8_t word_size = 32;
    uint32_t y_word = *(uint32_t *)plain_text;
    uint32_t x_word = *(((uint32_t *)plain_text) + 1);
    uint32_t *round_key_ptr = (uint32_t *)key_sched;
    uint32_t *word_ptr = (uint32_t *)cipher_text;
    uint32_t tmp;
    uint8_t i;

    for (i = 0; i < round_limit; i++) {
        tmp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        y_word = x_word;

        x_word = tmp ^ *(round_key_ptr + i);
    }

    *word_ptr = y_word;
    *(word_ptr + 1) = x_word;
}

void simon_encrypt_96(uint8_t round_limit, uint8_t *key_sched, uint8_t *plain_text, uint8_t *cipher_text) {
    const uint8_t word_size = 48;

    bword_48 bw = *(bword_48 *)plain_text;
    uint64_t y_word = bw.data;

    bw = *((bword_48 *)(plain_text + 6));
    uint64_t x_word = bw.data;

    bword_48 *bw_ptr = (bword_48 *)cipher_text;

    uint32_t tmp;
    uint8_t i;

    for (i = 0; i < round_limit; i++) {
        tmp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        y_word = x_word;

        x_word = (tmp ^ (*((bword_48 *)(key_sched + (i * 6)))).data) & 0xFFFFFFFFFFFF;
    }

    bw.data = y_word;
    *bw_ptr = bw;

    bw.data = x_word;
    bw_ptr = (bword_48 *)(cipher_text + 6);
    *bw_ptr = bw;
}

void simon_encrypt_128(uint8_t round_limit, uint8_t *key_sched, uint8_t *plain_text, uint8_t *cipher_text) {
    const uint8_t word_size = 64;
    uint64_t y_word = *(uint64_t *)plain_text;
    uint64_t x_word = *(((uint64_t *)plain_text) + 1);
    uint64_t *round_key_ptr = (uint64_t *)key_sched;
    uint64_t *word_ptr = (uint64_t *)cipher_text;
    uint64_t tmp;
    uint8_t i;

    for (i = 0; i < round_limit; i++) {
        tmp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        y_word = x_word;

        x_word = tmp ^ *(round_key_ptr + i);
    }

    *word_ptr = y_word;
    *(word_ptr + 1) = x_word;
}

uint8_t simon_decrypt(simon_cipher cipher, void *cipher_text, void *plain_text) {
    if (cipher.simon_config == simon_64_32) {
        simon_decrypt_32(cipher.key_sched, cipher_text, plain_text);
    }
    else if(cipher.simon_config <= simon_96_48) {
        simon_decrypt_48(cipher.round_limit, cipher.key_sched, cipher_text, plain_text);
    }
    else if(cipher.simon_config <= simon_128_64) {
        simon_decrypt_64(cipher.round_limit, cipher.key_sched, cipher_text, plain_text);
    }
    else if(cipher.simon_config <= simon_144_96) {
        simon_decrypt_96(cipher.round_limit, cipher.key_sched, cipher_text, plain_text);
    }
    else if(cipher.simon_config <= simon_256_128) {
        simon_decrypt_128(cipher.round_limit, cipher.key_sched, cipher_text, plain_text);
    }
    else return -1;

    return 0;
}

void simon_decrypt_32(uint8_t *key_sched, uint8_t *cipher_text, uint8_t *plain_text) {
    const uint8_t word_size = 16;
    uint16_t x_word = *(uint16_t *)cipher_text;
    uint16_t y_word = *(((uint16_t *)cipher_text) + 1);
    uint16_t *round_key_ptr = (uint16_t *)key_sched;
    uint16_t * word_ptr = (uint16_t *)plain_text;
    uint16_t tmp;
    int8_t i;

    for(i = 31; i >= 0; i--) {
        tmp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        y_word = x_word;

        x_word = tmp ^ *(round_key_ptr + i);
    }

    *word_ptr = x_word;
    *(word_ptr + 1) = y_word;
}

void simon_decrypt_48(uint8_t round_limit, uint8_t *key_sched, uint8_t *cipher_text, uint8_t *plain_text) {
    const uint8_t word_size = 24;

    bword_24 bw = *(bword_24 *)cipher_text;
    uint32_t x_word = bw.data;

    bw = *((bword_24 *)(cipher_text + 3));
    uint32_t y_word = bw.data;

    bword_24 *bw_ptr = (bword_24 *)plain_text;

    uint32_t tmp;
    int8_t i;

    for(i = round_limit - 1 ; i >= 0; i--) {
        tmp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        y_word = x_word;

        x_word = (tmp ^ (*((bword_24 *)(key_sched + (i * 3)))).data) & 0xFFFFFF;
    }

    bw.data = x_word;
    *bw_ptr = bw;

    bw.data = y_word;
    bw_ptr = (bword_24 *)(plain_text + 3);
    *bw_ptr = bw;
}

void simon_decrypt_64(uint8_t round_limit, uint8_t *key_sched, uint8_t *cipher_text, uint8_t *plain_text) {
    const uint8_t word_size = 32;
    uint32_t x_word = *(uint32_t *)cipher_text;
    uint32_t y_word = *(((uint32_t *)cipher_text) + 1);
    uint32_t *round_key_ptr = (uint32_t *)key_sched;
    uint32_t *word_ptr = (uint32_t *)plain_text;
    uint32_t tmp;
    int8_t i;

    for(i = round_limit -1 ; i >= 0; i--) {
        tmp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        y_word = x_word;

        x_word = tmp ^ *(round_key_ptr + i);
    }

    *word_ptr = x_word;
    *(word_ptr + 1) = y_word;
}

void simon_decrypt_96(uint8_t round_limit, uint8_t *key_sched, uint8_t *cipher_text, uint8_t *plain_text) {
    const uint8_t word_size = 48;

    bword_48 bw = *(bword_48 *)cipher_text;
    uint64_t x_word = bw.data;

    bw = *((bword_48 *)(cipher_text + 6));
    uint64_t y_word = bw.data;

    bword_48 *bw_ptr = (bword_48 *)plain_text;

    uint64_t tmp;
    int8_t i;

    for(i = round_limit - 1; i >= 0; i--) {
        tmp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        y_word = x_word;

        x_word = (tmp ^ (*((bword_48 *)(key_sched + (i * 6)))).data) & 0xFFFFFFFFFFFF;
    }

    bw.data = x_word;
    *bw_ptr = bw;

    bw.data = y_word;
    bw_ptr = (bword_48 *)(plain_text + 6);
    *bw_ptr = bw;
}

void simon_decrypt_128(uint8_t round_limit, uint8_t *key_sched, uint8_t *cipher_text, uint8_t *plain_text) {
    const uint8_t word_size = 64;
    uint64_t x_word = *(uint64_t *)cipher_text;
    uint64_t y_word = *(((uint64_t *)cipher_text) + 1);
    uint64_t *round_key_ptr = (uint64_t *)key_sched;
    uint64_t *word_ptr = (uint64_t *)plain_text;
    uint64_t tmp;
    int8_t i;

    for(i = round_limit - 1; i >= 0; i--) {
        tmp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        y_word = x_word;

        x_word = tmp ^ *(round_key_ptr + i);
    }

    *word_ptr = x_word;
    *(word_ptr + 1) = y_word;
}

void start(enum config_t simon_config) {
    simon_cipher *cipher = (simon_cipher *)malloc(sizeof(simon_cipher));
    char plain_text[] = {"I am your father, Luke."};
    char key[] = {"No!"};
    char cipher_text[sizeof(plain_text)] = {};
    printf("Test line: %s \n", plain_text);
    printf("Key line: %s \n", key);
    simon_init(cipher, simon_config, key);
    simon_encrypt(*cipher, plain_text, cipher_text);
    printf("Encrypted line: %s \n", cipher_text);
    simon_decrypt(*cipher, cipher_text, plain_text);
    printf("Decrypted line: %s \n", plain_text);
}

int main() {
    enum config_t simon_config;

    simon_config = simon_64_32;
    printf("Cipher format: simon_64_32\n");
    start(simon_config);
    printf("\n");

    simon_config = simon_96_48;
    printf("Cipher format: simon_96_48\n");
    start(simon_config);
    printf("\n");

    simon_config = simon_128_64;
    printf("Cipher format: simon_128_64\n");
    start(simon_config);
    printf("\n");

    simon_config = simon_144_96;
    printf("Cipher format: simon_144_96\n");
    start(simon_config);
    printf("\n");

    simon_config = simon_256_128;
    printf("Cipher format: simon_256_128\n");
    start(simon_config);
    printf("\n");

    return 0;
}

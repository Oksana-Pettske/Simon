#ifndef SIMON_C_SIMON_H
#define SIMON_C_SIMON_H

enum config_t {
    simon_64_32,
    simon_96_48,
    simon_128_64,
    simon_144_96,
    simon_256_128
};

typedef struct {
    enum config_t simon_config;
    uint8_t block_size;
    uint8_t key_size;
    uint8_t round_limit;
    uint8_t init_vector[16];
    uint8_t counter[16];
    uint8_t key_sched[576];
    uint8_t z_seq;
} simon_cipher;

typedef struct {
    uint32_t data: 24;
} bword_24;

typedef struct {
    uint64_t data: 48;
} bword_48;

uint8_t simon_init(simon_cipher *cipher, enum config_t simon_config, void *key);
uint8_t simon_encrypt(simon_cipher cipher, void *plain_text, void *cipher_text);
uint8_t simon_decrypt(simon_cipher cipher, void *cipher_text, void *plain_text);

void simon_encrypt_32(uint8_t *key_sched, uint8_t *plain_text, uint8_t *cipher_text);
void simon_encrypt_48(uint8_t round_limit, uint8_t *key_sched, uint8_t *plaint_text, uint8_t *cipher_text);
void simon_encrypt_64(uint8_t round_limit, uint8_t *key_sched, uint8_t *plaint_text, uint8_t *cipher_text);
void simon_encrypt_96(uint8_t round_limit, uint8_t *key_sched, uint8_t *plaint_text, uint8_t *cipher_text);
void simon_encrypt_128(uint8_t round_limit, uint8_t *key_sched, uint8_t *plaint_text, uint8_t *cipher_text);

void simon_decrypt_32(uint8_t *key_sched, uint8_t *cipher_text, uint8_t *plain_text);
void simon_decrypt_48(uint8_t round_limit, uint8_t *key_sched, uint8_t *cipher_text, uint8_t *plain_text);
void simon_decrypt_64(uint8_t round_limit, uint8_t *key_sched, uint8_t *cipher_text, uint8_t *plain_text);
void simon_decrypt_96(uint8_t round_limit, uint8_t *key_sched, uint8_t *cipher_text, uint8_t *plain_text);
void simon_decrypt_128(uint8_t round_limit, uint8_t *key_sched, uint8_t *cipher_text, uint8_t *plain_text);

#endif

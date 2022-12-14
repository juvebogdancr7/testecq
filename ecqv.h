/*
 * ECQV Public/Private Key Pair Generator Command Line Tool (ecqv-keygen)
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef ECQV_KG_ECQV_H
#define ECQV_KG_ECQV_H

struct ecqv_opt_t {
	char *out;
	char *in;
	char *key;
	char *log;
	char *hash;
};

struct ecqv_gen_t;

void ecqv_cleanup(void);
void ecqv_initialize(void);
int ecqv_generate_keypair(struct ecqv_gen_t *ecqv_gen);
int ecqv_export_keypair(struct ecqv_gen_t *ecqv_gen);
int ecqv_verify_keypair(struct ecqv_gen_t *ecqv_gen);
int ecqv_free(struct ecqv_gen_t *ecqv_gen);
int ecqv_create(struct ecqv_gen_t **ecqv_gen,
                const struct ecqv_opt_t *ecqv_opt);

int ecqv_cert_request(struct ecqv_gen_t *ecqv_gen);
int ecqv_cert_generate(struct ecqv_gen_t *ecqv_gen);
int ecqv_pk_extraction(struct ecqv_gen_t *ecqv_gen);
int ecqv_cert_reception(struct ecqv_gen_t *ecqv_gen);

//encrypt/decrypt
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

#endif

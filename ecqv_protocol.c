/*
 * ECQV Public/Private Key Pair Generator Command Line Tool (ecqv-keygen)
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "ecqv.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#define ECQV_KG_VERSION "0.1"

#define ECQV_KG_CMD_INFO \
	"ECQV Public/Private Key Pair Generator %s\n" \
	"Create EC key pair with implicit certificate.\n" \
	"Usage: %s [OPTION...] FILE\n" \
	"  -i <arg>                       Identity file, default: STDIN\n" \
	"  -o <arg>                       Output file, default: STDOUT\n" \
	"  -l <arg>                       Log file, default: no logging\n" \
	"  -h <arg>                       Hash function, default: SHA-1\n" \
	"Reads the private key of CA from the PEM file denoted by FILE.\n"

static struct ecqv_opt_t ecqv_opt;

static void print_usage_and_exit(int argc, char **argv)
{
	if (argc > 0) {
		fprintf(stderr, ECQV_KG_CMD_INFO, ECQV_KG_VERSION, argv[0]);
	}

	exit(EXIT_FAILURE);
}

static void parse_cmd_options(int argc, char **argv)
{
	int opt;

	if (argc < 2) {
		print_usage_and_exit(argc, argv);
	}

	memset(&ecqv_opt, 0, sizeof(ecqv_opt));
	opterr = 0; /* To inhibit error messages */

	while ((opt = getopt(argc, argv, "i:o:l:h:")) != -1) {
		switch (opt) {
			case 'i':
				ecqv_opt.in = optarg;
				break;

			case 'o':
				ecqv_opt.out = optarg;
				break;

			case 'l':
				ecqv_opt.log = optarg;
				break;

			case 'h':
				ecqv_opt.hash = optarg;
				break;

			default:
				/* If unknown option print info */
				print_usage_and_exit(argc, argv);
				break;
		}
	}

	/* Get the CA private key file */
	ecqv_opt.key = argv[argc - 1];
}

int main(int argc, char **argv)
{
	struct ecqv_gen_t *ecqv_gen = NULL;
    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"012345678901";
	/* Message to be encrypted */
    unsigned char *plaintext = (unsigned char *)"The quick brown fox";
	unsigned char *ciphertext = malloc(sizeof(char) * 128);
	unsigned char tag[128];
	/* Buffer for the decrypted text */
    unsigned char decryptedtext[128];
	int ciphertext_len, decryptedtext_len;
	parse_cmd_options(argc, argv);
	/* Clean ECQV resources at exit */
	atexit(ecqv_cleanup);
	ecqv_initialize();

	if (ecqv_create(&ecqv_gen, &ecqv_opt) == -1) {
		goto ERROR;
	}

	if(ecqv_cert_request(ecqv_gen) == -1) {
		goto ERROR;
	}

	if(ecqv_cert_generate(ecqv_gen) == -1) {
		goto ERROR;
	}
	
	if(ecqv_pk_extraction(ecqv_gen) == -1) {
		goto ERROR;
	}

	if(ecqv_cert_reception(ecqv_gen) == -1) {
		goto ERROR;
	}

	if (ecqv_verify_keypair(ecqv_gen) == -1) {
		goto ERROR;
	}

	if (ecqv_export_keypair(ecqv_gen) == -1) {
		goto ERROR;
	}
	/* Encrypt the plaintext */
    // ciphertext_len = gcm_encrypt(plaintext, strlen ((char *)plaintext), key, iv, 12, ciphertext, tag);
	// if(ciphertext_len == -1) {
	// 	goto ERROR;
	// }

    // /* Do something useful with the ciphertext here */
    // printf("Ciphertext is:\n");
    // BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
	// printf("Ciphertext length is %d\n", ciphertext_len);

	// /* Decrypt the ciphertext */
    // decryptedtext_len = gcm_decrypt(ciphertext, ciphertext_len, tag, key, iv, 12, decryptedtext);
    // /* Add a NULL terminator. We are expecting printable text */
    // decryptedtext[decryptedtext_len] = '\0';

    // /* Show the decrypted text */
    // printf("Decrypted text is:\n");
    // printf("%s\n", decryptedtext);


	ecqv_free(ecqv_gen);
	return EXIT_SUCCESS;
ERROR:
	printf("Desila se greska\n");
	if (ecqv_gen) {
		ecqv_free(ecqv_gen);
	}

	return EXIT_FAILURE;
}

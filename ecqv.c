/*
 * ECQV Public/Private Key Pair Generator Command Line Tool (ecqv-keygen)
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "ecqv.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

struct ecqv_gen_t {
	BN_CTX *ctx;
	BIGNUM *order;
	BIGNUM *cofactor;
	EC_GROUP const *group;
	EC_KEY *ca_key;
	EC_KEY *cl_key;
	EC_POINT *Pu;
	EC_POINT *p_alphaG;
	EC_POINT *p_Qa;
	BIGNUM *r;
	BIGNUM *a;
	BIGNUM *k;
	BIGNUM *e;
	EVP_MD const *hash;
	FILE *in;
	FILE *out;
	FILE *key;
	FILE *log;
};

#define ECQV_HASH EVP_sha256()

static void ecqv_log_bn(struct ecqv_gen_t *gen, const char *label, const BIGNUM *bn)
{
	char *str;

	if (!gen->log) {
		return;
	}

	str = BN_bn2hex(bn);

	if (!str) {
		fprintf(stderr, "Log: error converting bignum to hex.\n");
		return;
	}

	fprintf(gen->log, "BIGNUM (%s): %s\n", label, str);
	fflush(gen->log);
	OPENSSL_free(str);
}

static void ecqv_log_point(struct ecqv_gen_t *gen, const char *label, const EC_POINT *point)
{
	char *str;

	if (!gen->log) {
		return;
	}

	str = EC_POINT_point2hex(gen->group, point,
	                         POINT_CONVERSION_COMPRESSED, gen->ctx);

	if (!str) {
		fprintf(stderr, "Log: error converting point to hex.\n");
		return;
	}

	fprintf(gen->log, "EC_POINT (%s): %s\n", label, str);
	fflush(gen->log);
	OPENSSL_free(str);
}

static void ecqv_log_key(struct ecqv_gen_t *gen, const char *label, const EC_KEY *key)
{
	if (!gen->log) {
		return;
	}

	fprintf(gen->log, "EC_KEY (%s):\n", label);

	if (EC_KEY_print_fp(gen->log, key, 3) == 0) {
		fprintf(stderr, "Log: error printing EC key.\n");
		return;
	}

	fflush(gen->log);
}

static FILE *ecqv_open_file(const char *name, const char *mode)
{
	FILE *file = fopen(name, mode);

	if (!file) {
		fprintf(stderr, "Error opening file '%s': %s.\n",
		        name, strerror(errno));
		return NULL;
	}

	return file;
}

static EC_KEY *ecqv_read_private_key(FILE *file)
{
	EVP_PKEY *pk = PEM_read_PrivateKey(file, NULL, NULL, NULL);
	EC_KEY *key;

	if (!pk) {
		fprintf(stderr, "Error reading private key file.\n");
		return NULL;
	}

	key = EVP_PKEY_get1_EC_KEY(pk);

	if (!key) {
		fprintf(stderr, "Error loading EC private key.\n");
	}

	EVP_PKEY_free(pk);
	return key;
}

static int ecqv_write_private_key(struct ecqv_gen_t *ecqv_gen)
{
	EVP_PKEY *evp_pkey;
	EC_KEY *ec_key;
	evp_pkey = EVP_PKEY_new();

	if (!evp_pkey) {
		return -1;
	}

	ec_key = EC_KEY_dup(ecqv_gen->cl_key);

	if (!ec_key) {
		return -1;
	}

	if (EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key) == 0) {
		return -1;
	}

	if (PEM_write_PrivateKey(ecqv_gen->out, evp_pkey,
	                         NULL, NULL, 0, 0, NULL) == 0) {
		EVP_PKEY_free(evp_pkey);
		return -1;
	}

	EVP_PKEY_free(evp_pkey);
	return 0;
}

static int ecqv_write_impl_cert(struct ecqv_gen_t *ecqv_gen)
{
	BIO *b64 = NULL, *bio = NULL;
	unsigned char *buf = NULL;
	size_t buf_len;
	buf_len = EC_POINT_point2oct(ecqv_gen->group, ecqv_gen->Pu,
	                             POINT_CONVERSION_COMPRESSED,
	                             NULL, 0, ecqv_gen->ctx);

	if (buf_len == 0) {
		goto ERROR;
	}

	buf = OPENSSL_malloc(buf_len);

	if (!buf) {
		goto ERROR;
	}

	buf_len = EC_POINT_point2oct(ecqv_gen->group, ecqv_gen->Pu,
	                             POINT_CONVERSION_COMPRESSED,
	                             buf, buf_len, ecqv_gen->ctx);

	if (buf_len == 0) {
		goto ERROR;
	}
	printf("%zd\n", buf_len);

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, 0);
	bio = BIO_new_fp(ecqv_gen->out, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	fprintf(ecqv_gen->out, "-----BEGIN IMPLICIT CERTIFICATE-----\n");
	BIO_write(bio, buf, buf_len);
	(void)BIO_flush(bio);
	fprintf(ecqv_gen->out, "-----END IMPLICIT CERTIFICATE-----\n");
	OPENSSL_free(buf);
	BIO_free_all(bio);
	return 0;
ERROR:

	if (buf) {
		OPENSSL_free(buf);
	}

	if (bio) {
		BIO_free_all(bio);
	}

	return -1;
}

static int ecqv_create_bn_from_id(struct ecqv_gen_t *ecqv_gen)
{
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char *buf = NULL;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	long int file_len;
	size_t buf_len;

	if (!ecqv_gen->e) {
		ecqv_gen->e = BN_new();
	}

	if (!ecqv_gen->e) {
		return -1;
	}

	md_ctx = EVP_MD_CTX_create();

	if (!md_ctx) {
		return -1;
	}

	if (EVP_DigestInit_ex(md_ctx, ecqv_gen->hash, 0) == 0) {
		goto ERROR;
	}

	buf_len = EC_POINT_point2oct(ecqv_gen->group, ecqv_gen->Pu,
	                             POINT_CONVERSION_COMPRESSED,
	                             NULL, 0, ecqv_gen->ctx);

	if (buf_len == 0) {
		goto ERROR;
	}

	buf = OPENSSL_malloc(buf_len);

	if (!buf) {
		goto ERROR;
	}

	if (EC_POINT_point2oct(ecqv_gen->group, ecqv_gen->Pu,
	                       POINT_CONVERSION_COMPRESSED,
	                       buf, buf_len, ecqv_gen->ctx) == 0) {
		goto ERROR;
	}

	if (EVP_DigestUpdate(md_ctx, buf, buf_len) == 0) {
		goto ERROR;
	}

	if (fseek(ecqv_gen->in, 0L, SEEK_END) == -1) {
		goto ERROR;
	}

	file_len = ftell(ecqv_gen->in);
	rewind(ecqv_gen->in);

	if (file_len > 0) {
		unsigned char *tmp_buf;
		tmp_buf = realloc(buf, file_len);

		if (!tmp_buf) {
			goto ERROR;
		}

		buf = tmp_buf;
		file_len = fread(buf, file_len, 1, ecqv_gen->in);
		EVP_DigestUpdate(md_ctx, buf, file_len);
	} else {
		fprintf(stderr, "No identity data supplied.\n");
		goto ERROR;
	}

	if (EVP_DigestFinal_ex(md_ctx, md_value, &md_len) == 0) {
		goto ERROR;
	}
	if (!BN_bin2bn(md_value, md_len, ecqv_gen->e)) {
		goto ERROR;
	}
	// BIGNUM *eFinal = BN_new();
	// if(BN_mod(eFinal, ecqv_gen->e, ecqv_gen->order, ecqv_gen->ctx) == 0) {
	// 	goto ERROR;
	// }
	// //ecqv_gen->e = eFinal;
	ecqv_log_bn(ecqv_gen, "e", ecqv_gen->e);
	EVP_MD_CTX_destroy(md_ctx);
	OPENSSL_free(buf);
	return 0;
ERROR:

	if (md_ctx) {
		EVP_MD_CTX_destroy(md_ctx);
	}

	if (buf) {
		OPENSSL_free(buf);
	}
	return -1;
}

void ecqv_initialize(void)
{
	OpenSSL_add_all_digests();
}

void ecqv_cleanup(void)
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

int ecqv_create(struct ecqv_gen_t **ecqv_gen, const struct ecqv_opt_t *opt)
{
	struct ecqv_gen_t *ecqv;
	const EC_POINT *G;

	if (!opt->key) {
		fprintf(stderr, "No CA private key given.\n");
		return -1;
	}

	ecqv = OPENSSL_malloc(sizeof(*ecqv));

	if (!ecqv) {
		return -1;
	}

	memset(ecqv, 0, sizeof(*ecqv));

	if (opt->hash) {
		ecqv->hash = EVP_get_digestbyname(opt->hash);
	} else {
		ecqv->hash = ECQV_HASH;
	}

	if (!ecqv->hash) {
		fprintf(stderr, "Hash '%s' not found.\n", opt->hash);
		goto ERROR;
	}

	ecqv->key = ecqv_open_file(opt->key, "rb");

	if (!ecqv->key) {
		goto ERROR;
	}

	ecqv->ca_key = ecqv_read_private_key(ecqv->key);

	if (!ecqv->ca_key) {
		goto ERROR;
	}

	ecqv->in = (opt->in) ? ecqv_open_file(opt->in, "rb") : stdin;

	if (!ecqv->in) {
		goto ERROR;
	}

	ecqv->log = (opt->log) ? ecqv_open_file(opt->log, "wb") : NULL;

	if (!ecqv->log && opt->log) {
		goto ERROR;
	}

	ecqv->out = (opt->out) ? ecqv_open_file(opt->out, "wb") : stdout;

	if (opt->out) {
		goto ERROR;
	}

	ecqv_log_key(ecqv, "CA", ecqv->ca_key);
	ecqv->ctx = BN_CTX_new();

	if (!ecqv->ctx) {
		goto ERROR;
	}

	ecqv->group = EC_KEY_get0_group(ecqv->ca_key);

	if (!ecqv->group) {
		fprintf(stderr, "Failed to get the group.\n");
		goto ERROR;
	}

	G = EC_GROUP_get0_generator(ecqv->group);

	if (!G) {
		fprintf(stderr, "Failed to get the generator.\n");
		goto ERROR;
	}

	ecqv_log_point(ecqv, "G", G);
	ecqv->order = BN_new();

	if (!ecqv->order) {
		goto ERROR;
	}

	if (EC_GROUP_get_order(ecqv->group, ecqv->order, 0) == 0) {
		fprintf(stderr, "Failed to get the order.\n");
		goto ERROR;
	}

	ecqv_log_bn(ecqv, "order", ecqv->order);

	ecqv->cofactor = BN_new();

	if (EC_GROUP_get_cofactor(ecqv->group, ecqv->cofactor, 0) == 0) {
		fprintf(stderr, "Failed to get the cofactor.\n");
		goto ERROR;
	}

	ecqv_log_bn(ecqv, "cofactor", ecqv->cofactor);
	*ecqv_gen = ecqv;
	return 0;
ERROR:

	if (ecqv) {
		ecqv_free(ecqv);
	}

	return -1;
}

int ecqv_free(struct ecqv_gen_t *ecqv_gen)
{
	if (ecqv_gen->ctx) {
		BN_CTX_free(ecqv_gen->ctx);
	}

	if (ecqv_gen->order) {
		BN_free(ecqv_gen->order);
	}

	if (ecqv_gen->ca_key) {
		EC_KEY_free(ecqv_gen->ca_key);
	}

	if (ecqv_gen->cl_key) {
		EC_KEY_free(ecqv_gen->cl_key);
	}

	if (ecqv_gen->Pu) {
		EC_POINT_free(ecqv_gen->Pu);
	}

	if (ecqv_gen->r) {
		BN_free(ecqv_gen->r);
	}

	if (ecqv_gen->k) {
		BN_free(ecqv_gen->k);
	}

	if (ecqv_gen->a) {
		BN_free(ecqv_gen->a);
	}

	if (ecqv_gen->e) {
		BN_free(ecqv_gen->e);
	}

	if (ecqv_gen->log) {
		fclose(ecqv_gen->log);
	}

	if (ecqv_gen->key) {
		fclose(ecqv_gen->key);
	}

	if (ecqv_gen->in) {
		fclose(ecqv_gen->in);
	}

	if (ecqv_gen->out) {
		fclose(ecqv_gen->out);
	}

	OPENSSL_free(ecqv_gen);
	return 0;
}

int ecqv_verify_keypair(struct ecqv_gen_t *ecqv_gen)
{
	if (EC_KEY_check_key(ecqv_gen->cl_key) == 0) {
		fprintf(stderr, "Public key check failed.\n");
		return -1;
	}

	// TODO: verify key as per the ECQV standard
	return 0;
}

int ecqv_export_keypair(struct ecqv_gen_t *ecqv_gen)
{
	if (ecqv_write_private_key(ecqv_gen) == -1) {
		fprintf(stderr, "Exporting key pair failed.\n");
		return -1;
	}

	if (ecqv_write_impl_cert(ecqv_gen) == -1) {
		fprintf(stderr, "Exporting certificate failed.\n");
		return -1;
	}

	return 0;
}

static int cert_request(struct ecqv_gen_t *ecqv_gen) {
	printf("CERT Request\n");
	// Input
	// 1. The elliptic curve domain parameters established by CA as determined in §3.2. Here group and order
	// 2. A string U representing U’s identity. Here in identity.txt file
	// Actions
	// 1. Generate an EC key pair (a , p_alphaG ) associated with the established elliptic curve domain

	if (!ecqv_gen->a) {
		ecqv_gen->a = BN_new();
	}

	if (!ecqv_gen->a) {
		return -1;
	}

	if (BN_rand_range(ecqv_gen->a, ecqv_gen->order) == 0) {
		return -1;
	}

	ecqv_log_bn(ecqv_gen, "alpha", ecqv_gen->a);
	ecqv_gen->p_alphaG = EC_POINT_new(ecqv_gen->group);

	if (!ecqv_gen->p_alphaG) {
		return -1;
	}

	if (EC_POINT_mul(ecqv_gen->group, ecqv_gen->p_alphaG, ecqv_gen->a,
	                 NULL, NULL, NULL) == 0) {
		return -1;
	}

	// 2. Convert p_alphaG to the octet string alphaG using the Elliptic-Curve-Point-to-Octet-String.
	ecqv_log_point(ecqv_gen, "alphaG", ecqv_gen->p_alphaG);
	return 0;
}

static int cert_generate(struct ecqv_gen_t *ecqv_gen) {
	printf("Cert generate\n");
	const BIGNUM *c;
	BIGNUM *ek = BN_new();
	// Input
	// 1. The elliptic curve domain parameters established by CA.
	// 2. The hash function H selected by CA. 
	// 3. CA’s private key dCA.
	// 4. A certificate request (identity, p_alphaG).
	// Actions

	// 1. Validate p_alphaG using the public key validation technique. If the validation primitive outputs ‘invalid’, output ‘invalid’ and stop.
	if (EC_POINT_is_on_curve(ecqv_gen->group, ecqv_gen->p_alphaG, ecqv_gen->ctx) == 0) {
		fprintf(stderr, "Certificate request failed. pont not on curve.\n");
		return -1;
	}	
	// 2. Generate an EC key pair (k, p_kG) associated with the established elliptic curve domain parameters using the key pair generation primitive.
	EC_POINT *p_kG = NULL;
	if (!ecqv_gen->k) {
		ecqv_gen->k = BN_new();
	}

	if (!ecqv_gen->k) {
		goto ERROR;
	}

	if (BN_rand_range(ecqv_gen->k, ecqv_gen->order) == 0) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "k", ecqv_gen->k);
	p_kG = EC_POINT_new(ecqv_gen->group);

	if (!p_kG) {
		goto ERROR;
	}

	if (EC_POINT_mul(ecqv_gen->group, p_kG, ecqv_gen->k,
	                 NULL, NULL, NULL) == 0) {
		goto ERROR;
	}

	ecqv_log_point(ecqv_gen, "kG", p_kG);
	// 3. Compute the elliptic curve point PU = p_alphaG + p_kG.
	if (!ecqv_gen->Pu) {
		ecqv_gen->Pu = EC_POINT_new(ecqv_gen->group);
	}

	if (EC_POINT_add(ecqv_gen->group, ecqv_gen->Pu,
	                 ecqv_gen->p_alphaG, p_kG, NULL) == 0) {
		goto ERROR;
	}

	// 4. Convert PU to the octet string PU using the Elliptic-Curve-Point-to-Octet-String conversion
	ecqv_log_point(ecqv_gen, "Pu", ecqv_gen->Pu);
	EC_POINT_free(p_kG);

	// 5. Use the selected hash function to compute e = Hn(CertU ), an integer modulo n.
	if (ecqv_create_bn_from_id(ecqv_gen) == -1) {
		fprintf(stderr, "Creating bignum from the identity failed.\n");
		goto ERROR;
	}
	// 6. Compute the integer r = ek + dCA (mod n).
	if (!ek) {
		return -1;
	}

	if (BN_mul(ek, ecqv_gen->e, ecqv_gen->k, ecqv_gen->ctx) == 0) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "ek", ek);

	if (!ecqv_gen->r) {
		ecqv_gen->r = BN_new();
	}

	if (!ecqv_gen->r) {
		goto ERROR;
	}

	c = EC_KEY_get0_private_key(ecqv_gen->ca_key);

	if (!c) {
		goto ERROR;
	}

	if (BN_mod_add(ecqv_gen->r, ek, c, ecqv_gen->order, ecqv_gen->ctx) == 0) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "r", ecqv_gen->r);
	BN_free(ek);	
	return 0;
ERROR:
	printf("Error je\n");
	if (p_kG) {
		EC_POINT_free(p_kG);
	}

	if (ek) {
		BN_free(ek);
	}

	return -1;
}

static int pk_extraction(struct ecqv_gen_t *ecqv_gen) {
	printf("Extract PK\n");
	// Input
	// 1. The elliptic curve domain parameters established by CA.
	// 2. The hash function H selected by CA.
	// 3. CA’s public key QCA.
	// 4. The certificate CertU .
	// Actions
	// 1. Validate PU using the public key validation technique. If the validation primitive outputs ‘invalid’, output ‘invalid’ and stop. Not needed fot this setup
	// 2. Use the selected hash function to compute e = Hn(CertU ), an integer modulo n. We already have this computed and saved
	// 2. Compute the point pQa = ePU + QCA.
	EC_POINT *ePu = NULL, *p_Qa = NULL;
	const EC_POINT *p_Qc = NULL;

	ePu = EC_POINT_new(ecqv_gen->group);

	if (!ePu) {
		goto ERROR;
	}

	if (EC_POINT_mul(ecqv_gen->group, ePu, NULL,
	                 ecqv_gen->Pu, ecqv_gen->e, NULL) == 0) {
		goto ERROR;
	}

	ecqv_log_point(ecqv_gen, "ePu", ePu);
	p_Qa = EC_POINT_new(ecqv_gen->group);

	if (!p_Qa) {
		goto ERROR;
	}

	p_Qc = EC_KEY_get0_public_key(ecqv_gen->ca_key);

	if (!p_Qc) {
		goto ERROR;
	}

	if (EC_POINT_add(ecqv_gen->group, p_Qa, ePu, p_Qc, 0) == 0) {
		goto ERROR;
	}

	ecqv_log_point(ecqv_gen, "p_Qa", p_Qa);
	ecqv_gen->p_Qa = p_Qa;
	EC_POINT_free(ePu);
	return 0;
ERROR:

	if (ePu) {
		EC_POINT_free(ePu);
	}

	return -1;
}

static int cert_reception(struct ecqv_gen_t *ecqv_gen) {
	printf("Cert reception\n");
	BIGNUM *ealpha = NULL, *a = NULL;
	ealpha = BN_new();
	EC_POINT *p_Qa_prim;
	p_Qa_prim = EC_POINT_new(ecqv_gen->group);
	// Input
	// 1. The elliptic curve domain parameters established by CA.
	// 2. The hash function H selected by CA.
	// 3. The private value a generated by Client.
	// 4. The output of Cert Generate: the certificate CertU and the private key contribution data (r)

	// Actions
	// 1. Compute the public key p_Qa using Cert PK Extraction (or equivalent computations). Already done here
	// 2. Use the selected hash function to compute e = Hn(CertU ), an integer modulo n. Already done as well
	// 3. Compute the private key dU = r + ea (mod n).
	if (!ealpha || BN_mul(ealpha, ecqv_gen->e,
	                      ecqv_gen->a, ecqv_gen->ctx) == 0) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "ealpha", ealpha);
	a = BN_new();

	if (!a) {
		goto ERROR;
	}

	if (BN_mod_add(a, ealpha, ecqv_gen->r,
	               ecqv_gen->order, ecqv_gen->ctx) == 0) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "a", a);
	// 4. Compute p_Qa = a * G.
	if (EC_POINT_mul(ecqv_gen->group, p_Qa_prim, a,
	                 NULL, NULL, NULL) == 0) {
		return -1;
	}
	ecqv_log_point(ecqv_gen, "p_Qa_prim", p_Qa_prim);
	
	if(EC_POINT_cmp(ecqv_gen->group, ecqv_gen->p_Qa, p_Qa_prim, ecqv_gen->ctx) != 0) {
		printf("Reception of certificate failed.\n");
		goto ERROR;
	}

	ecqv_gen->cl_key = EC_KEY_new();

	if (!ecqv_gen->cl_key) {
		goto ERROR;
	}

	if (EC_KEY_set_group(ecqv_gen->cl_key, ecqv_gen->group) == 0) {
		goto ERROR;
	}

	if (EC_KEY_set_private_key(ecqv_gen->cl_key, a) == 0) {
		goto ERROR;
	}

	if (EC_KEY_set_public_key(ecqv_gen->cl_key, p_Qa_prim) == 0) {
		goto ERROR;
	}

	ecqv_log_key(ecqv_gen, "CLIENT", ecqv_gen->cl_key);
	EC_POINT_free(p_Qa_prim);
	BN_free(ealpha);
	BN_free(a);
	return 0;
ERROR:
	printf("Error je\n");
	if (p_Qa_prim) {
		EC_POINT_free(p_Qa_prim);
	}

	if (ealpha) {
		BN_free(ealpha);
	}

	if (a) {
		BN_free(a);
	}

	return -1;
}

int ecqv_cert_request(struct ecqv_gen_t *ecqv_gen)
{
	if (cert_request(ecqv_gen) == -1) {
		fprintf(stderr, "Generating request failed.\n");
		return -1;
	}

	return 0;
}

int ecqv_cert_generate(struct ecqv_gen_t *ecqv_gen)
{
	if (cert_generate(ecqv_gen) == -1) {
		fprintf(stderr, "Generating certificate failed.\n");
		return -1;
	}

	return 0;
}

int ecqv_pk_extraction(struct ecqv_gen_t *ecqv_gen)
{
	if (pk_extraction(ecqv_gen) == -1) {
		fprintf(stderr, "Extracting public key failed.\n");
		return -1;
	}

	return 0;
}

int ecqv_cert_reception(struct ecqv_gen_t *ecqv_gen)
{
	if (cert_reception(ecqv_gen) == -1) {
		fprintf(stderr, "Certificate reception failed.\n");
		return -1;
	}

	return 0;
}


//encrypt/decrypt
int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len = -1;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return -1;

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        return -1;

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    // /*
    //  * Provide the message to be encrypted, and obtain the encrypted output.
    //  * EVP_EncryptUpdate can be called multiple times if necessary
    //  */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    // /*
    //  * Finalise the encryption. Normally ciphertext bytes may be written at
    //  * this stage, but this does not occur in GCM mode
    //  */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        return -1;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return -1;

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        return -1;

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        return -1;

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}
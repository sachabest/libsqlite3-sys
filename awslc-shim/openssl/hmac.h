/*
 * p2p patch: lets SQLCipher's OpenSSL provider (sqlcipher.c) build against
 * AWS-LC. The provider's HMAC uses the OpenSSL 3 EVP_MAC and OSSL_PARAM
 * APIs, which AWS-LC does not have. This header supplies the few calls and
 * types it uses, on top of AWS-LC's HMAC_* functions. It stands in front of
 * AWS-LC's <openssl/hmac.h> on the include path, so sqlcipher.c itself is
 * unchanged and its own feature-test macros come before any system header.
 */
#ifndef SQLCIPHER_AWSLC_SHIM_H
#define SQLCIPHER_AWSLC_SHIM_H

#ifdef _MSC_VER
/* MSVC has no #include_next; the build passes the path of AWS-LC's header. */
#include SQLCIPHER_AWSLC_HMAC_H
#else
#include_next <openssl/hmac.h>
#endif
#include <openssl/digest.h>
#include <stddef.h>
#include <string.h>

#ifndef OPENSSL_IS_AWSLC
#error "awslc-shim/openssl/hmac.h must be built against AWS-LC"
#endif

typedef struct {
  const char *key;
  unsigned int data_type;
  void *data;
  size_t data_size;
  size_t return_size;
} OSSL_PARAM;

#define OSSL_PARAM_UTF8_STRING 4
#define OSSL_PARAM_END { NULL, 0, NULL, 0, 0 }

typedef struct { char unused; } EVP_MAC;
typedef HMAC_CTX EVP_MAC_CTX;

static EVP_MAC sqlcipher_awslc_hmac_algorithm;

static EVP_MAC *EVP_MAC_fetch(void *libctx, const char *name, const char *props) {
  (void)libctx; (void)props;
  return strcmp(name, "HMAC") == 0 ? &sqlcipher_awslc_hmac_algorithm : NULL;
}

static void EVP_MAC_free(EVP_MAC *mac) { (void)mac; }

static EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *mac) {
  (void)mac;
  return HMAC_CTX_new();
}

static void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx) { HMAC_CTX_free(ctx); }

/*
 * Only the "digest" parameter is understood, as sqlcipher.c passes it.
 * SQLCipher sizes its output buffer from the algorithm it is configured with
 * and then passes back whatever size EVP_MAC_final reported, so the buffer
 * size seen there proves nothing. The digest size is therefore checked here,
 * against the length the name promises, before anything can be written.
 */
static int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t key_len, const OSSL_PARAM *params) {
  const EVP_MD *md = NULL;
  size_t expected = 0;
  if(params == NULL || params[0].key == NULL || strcmp(params[0].key, "digest") != 0) return 0;
  if(strcmp((const char *)params[0].data, "sha1") == 0) { md = EVP_sha1(); expected = 20; }
  else if(strcmp((const char *)params[0].data, "sha256") == 0) { md = EVP_sha256(); expected = 32; }
  else if(strcmp((const char *)params[0].data, "sha512") == 0) { md = EVP_sha512(); expected = 64; }
  if(md == NULL || EVP_MD_size(md) != expected) return 0;
  return HMAC_Init_ex(ctx, key, key_len, md, NULL);
}

static int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t len) {
  return HMAC_Update(ctx, data, len);
}

/* A NULL out only reports the size, as in OpenSSL 3. */
static int EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out, size_t *out_len, size_t out_size) {
  unsigned int len = 0;
  if(out == NULL) {
    *out_len = HMAC_size(ctx);
    return 1;
  }
  if(out_size < HMAC_size(ctx)) return 0;
  if(!HMAC_Final(ctx, out, &len)) return 0;
  *out_len = len;
  return 1;
}

#endif

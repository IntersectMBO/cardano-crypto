#include <stdint.h>
#include <string.h>

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];

typedef ed25519_secret_key ed25519_encrypted_secret_key;

typedef uint8_t cryptonite_chacha_context[131];

extern void cryptonite_chacha_init(cryptonite_chacha_context *ctx, uint8_t nb_rounds, uint32_t keylen, const uint8_t *key, uint32_t ivlen, const uint8_t *iv);
extern void cryptonite_chacha_combine(uint8_t *dst, cryptonite_chacha_context *st, const uint8_t *src, uint32_t bytes);

extern void cryptonite_ed25519_publickey(const ed25519_secret_key, ed25519_public_key);
extern void cryptonite_ed25519_sign(const unsigned char *, size_t, const ed25519_secret_key, const ed25519_public_key, ed25519_signature);

static
void decrypt(uint8_t const*  key,
             uint32_t const  key_len,
             uint8_t const*  nonce,
             uint32_t const  nonce_len,
             uint8_t const   nb_rounds,
             ed25519_secret_key const encrypted_key /* in */,
             ed25519_secret_key       decrypted_key /* out */)
{
	cryptonite_chacha_context ctx;
	memset(&ctx, 0, sizeof(cryptonite_chacha_context));
	cryptonite_chacha_init(&ctx, nb_rounds, key_len, key, nonce_len, nonce);
	cryptonite_chacha_combine(decrypted_key, &ctx, encrypted_key, sizeof(ed25519_secret_key));
	memset(&ctx, 0, sizeof(cryptonite_chacha_context));
}

static uint8_t const CHACHA_NB_ROUNDS = 20;

void encrypted_to_public(ed25519_encrypted_secret_key const encrypted_key,
                         uint8_t const* key, uint32_t const key_len,
                         uint8_t const* nonce, uint32_t const nonce_len,
                         ed25519_public_key public_key)
{
	ed25519_secret_key priv_key;

	decrypt(key, key_len, nonce, nonce_len, CHACHA_NB_ROUNDS, encrypted_key, priv_key);
	cryptonite_ed25519_publickey(priv_key, public_key);

	memset(priv_key, 0, sizeof(ed25519_secret_key));
}

void encrypted_sign(ed25519_encrypted_secret_key const encrypted_key, uint8_t const* key, uint32_t const key_len,
                    uint8_t const* nonce, uint32_t const nonce_len,
                    uint8_t const* data, size_t const data_len
                    ed25519_signature signature)
{
	ed25519_secret_key priv_key;
	ed25519_public_key pub_key;

	decrypt(key, key_len, nonce, nonce_len, CHACHA_NB_ROUNDS, encrypted_key, priv_key);
	cryptonite_ed25519_publickey(priv_key, pub_key);
	cryptonite_ed25519_sign(data, data_len, priv_key, pub_key, signature);

	memset(priv_key, 0, sizeof(ed25519_secret_key));
}

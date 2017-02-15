#include <stdint.h>
#include <string.h>

#include <ed25519.h>

typedef uint8_t cryptonite_chacha_context[131];

extern void cryptonite_chacha_init(cryptonite_chacha_context *ctx, uint8_t nb_rounds, uint32_t keylen, const uint8_t *key, uint32_t ivlen, const uint8_t *iv);
extern void cryptonite_chacha_combine(uint8_t *dst, cryptonite_chacha_context *st, const uint8_t *src, uint32_t bytes);

void clear(void *buf, uint32_t const sz)
{
	/* FIXME - HERE we need to make sure the compiler is not going to remove the call */
	memset(buf, 0, sz);
}

static
void stretch(uint8_t *buf, uint32_t const buf_len, uint8_t const *pass, uint32_t const pass_len)
{
	/* FIXME - pbkdf2 here */
	memset(buf, 1, buf_len);
}

#define SYM_KEY_SIZE     32
#define SYM_NONCE_SIZE   8
#define SYM_BUF_SIZE     (SYM_KEY_SIZE+SYM_NONCE_SIZE)

#define ENCRYPTED_KEY_SIZE 32
#define PUBLIC_KEY_SIZE 32
#define CHAIN_CODE_SIZE 32

typedef struct {
	uint8_t ekey[ENCRYPTED_KEY_SIZE];
	uint8_t pkey[PUBLIC_KEY_SIZE];
	uint8_t cc[CHAIN_CODE_SIZE];
} encrypted_key;

static
void unencrypt_start
    (uint8_t const*  pass,
     uint32_t const  pass_len,
     encrypted_key const *encrypted_key /* in */,
     ed25519_secret_key  decrypted_key /* out */)
{
	uint8_t buf[SYM_BUF_SIZE];
	cryptonite_chacha_context ctx;
	static uint8_t const CHACHA_NB_ROUNDS = 20;

	memset(&ctx, 0, sizeof(cryptonite_chacha_context));

	/* generate BUF_SIZE bytes where first KEY_SIZE bytes is the key and NONCE_SIZE remaining bytes the nonce */
	stretch(buf, SYM_BUF_SIZE, pass, pass_len);
	cryptonite_chacha_init(&ctx, CHACHA_NB_ROUNDS, SYM_KEY_SIZE, buf, SYM_NONCE_SIZE, buf + SYM_KEY_SIZE);
	clear(buf, SYM_BUF_SIZE);
	cryptonite_chacha_combine(decrypted_key, &ctx, encrypted_key->ekey, ENCRYPTED_KEY_SIZE);
	clear(&ctx, sizeof(cryptonite_chacha_context));
}

static
void unencrypt_stop(ed25519_secret_key decrypted_key)
{
	clear(decrypted_key, sizeof(ed25519_secret_key));
}

void wallet_encrypted_to_public
    (encrypted_key const *encrypted_key,
     uint8_t const *pass, uint32_t const pass_len,
     ed25519_public_key public_key)
{
	ed25519_secret_key priv_key;

	unencrypt_start(pass, pass_len, encrypted_key, priv_key);
	cardano_crypto_ed25519_publickey(priv_key, public_key);
	unencrypt_stop(priv_key);
}

void wallet_encrypted_sign
    (encrypted_key const *encrypted_key, uint8_t const* pass, uint32_t const pass_len,
     uint8_t const *data, uint32_t const data_len,
     ed25519_signature signature)
{
	ed25519_secret_key priv_key;
	ed25519_public_key pub_key;

	unencrypt_start(pass, pass_len, encrypted_key, priv_key);
	cardano_crypto_ed25519_publickey(priv_key, pub_key);
	cardano_crypto_ed25519_sign(data, data_len, encrypted_key->cc, CHAIN_CODE_SIZE, priv_key, pub_key, signature);
	unencrypt_stop(priv_key);
}

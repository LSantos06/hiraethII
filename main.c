/* OpenSSL */
// Biblioteca de IO
#include <openssl/bio.h>
// Biblioteca de curva eliptica
#include <openssl/ec.h>
#include <openssl/pem.h>
// Biblioteca para tratamendo de BIGNUM
#include <openssl/bn.h>

/* secp256k1 */
// Biblioteca de curva eliptica
#include "../secp256k1/src/libsecp256k1-config.h"
#include "../secp256k1/include/secp256k1.h"
#include "../secp256k1/src/secp256k1.c"

// Curva eliptica utilizada na criptografia de chave publica do Bitcoin
#define DEFAULT_ELLIPTIC_CURVE "secp256k1"

int main() {
            
    /**** generate_keys ****/
    BIO *io_print = NULL;                   // Print OpenSSL
    EC_KEY *elliptic_curve = NULL;          // Curva eliptica OpenSSL

    int elliptic_curve_nid;                 // Nome da curva eliptica OpenSSL
    unsigned char *private_key = NULL;      // Chave privada em binario (32 bytes)

    secp256k1_context *ctx = NULL;          // Contexto
    secp256k1_callback *cb = NULL;          // Callback para tratamento de erros
    secp256k1_pubkey public_key;            // Chave publica em binario (64 bytes)

    /* Inicializacao da biblioteca OpenSSL */
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    /* Inicializacao da biblioteca secp256k1 */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    // Inicializacao das operacoes de multiplicacao
    secp256k1_ecmult_gen_context_init(&ctx->ecmult_gen_ctx);
    secp256k1_ecmult_gen_context_build(&ctx->ecmult_gen_ctx, cb);

    /* IO */
    // Alocacao para prints do IO
    io_print = BIO_new(BIO_s_file());
    io_print = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* Curva Eliptica */
    // Obtem o NID da curva eliptica escolhida
    elliptic_curve_nid = OBJ_txt2nid(DEFAULT_ELLIPTIC_CURVE);
    // Constroi a curva eliptica a partir do nome (NID)
    elliptic_curve = EC_KEY_new_by_curve_name(elliptic_curve_nid);
    // Flag utilizada construcao de curvas a partir do nome (NID)
    EC_KEY_set_asn1_flag(elliptic_curve, OPENSSL_EC_NAMED_CURVE);

    /* Geracao das chaves */
    // Geracao das chaves a partir da curva eliptica
    if (!(EC_KEY_generate_key(elliptic_curve)))
        BIO_printf(io_print, "Error generating public and private keys.");
    // Armazenamento da chave privada em bignum
    const BIGNUM *private_key_bignum = EC_KEY_get0_private_key(elliptic_curve);
    printf("Chave privada em BIGNUM: ");
    BN_print(io_print, private_key_bignum);
    printf("\n");
    // Chave privada em binario (32 bytes)
    private_key = malloc(BN_num_bytes(private_key_bignum));
    if (!(BN_bn2bin(private_key_bignum, private_key)))
        BIO_printf(io_print, "Error transforming private key to binary.");
    printf("\nChave privada em binario (unsigned char)[%d]: %s\n", BN_num_bytes(private_key_bignum), private_key);
    // Verificacao da validade da chave privada
    if (!(secp256k1_ec_seckey_verify(ctx, private_key)))
        BIO_printf(io_print, "Error validating the private key.");
    // Calculo da chave publica a partir da chave privada
    if (!(secp256k1_ec_pubkey_create(ctx, &public_key, private_key)))
        BIO_printf(io_print, "Error generating the public key.");
    printf("\nChave publica em binario (unsigned char)[%lu]: %s\n", sizeof((&public_key)->data), (&public_key)->data);

    /**** sign schnorr ****/
    unsigned char message[32] = "Charles Leclerc";
    unsigned char *private_key_message = malloc(strlen(private_key) + strlen(message) + 1);
    unsigned char hashed[32];
    int overflow = 0;
    int hashed_int;
    int nonce_int;

    secp256k1_sha256 hash;

    secp256k1_scalar hashed_scalar;
    secp256k1_scalar zero_scalar;
    secp256k1_scalar nonce;

    /* Assinatura Schnorr - R */
    // Let nonce = (scalar(0) + scalar(hash(bytes(private_key) || message))) mod group_order
    //      Fail if nonce = 0.
    // Let R = nonce G.

    // private_key_message = bytes(private_key) || message
    strcat(private_key_message, private_key);
    strcat(private_key_message, message);
    // hashed = hash(bytes(private_key) || message)
    secp256k1_sha256_initialize(&hash);
    secp256k1_sha256_write(&hash, private_key_message, strlen(private_key_message));
    secp256k1_sha256_finalize(&hash, hashed);
    // hashed_scalar = scalar(hash(bytes(private_key) || message))
    secp256k1_scalar_set_b32(&hashed_scalar, hashed, &overflow);
    printf("\nhashed = %s\n", &hashed);
    if (overflow)
        BIO_printf(io_print, "Overflow in int(hash(bytes(private_key) || message)).");
    // scalar(0)
    secp256k1_scalar_clear(&zero_scalar);
    if (overflow || !(secp256k1_scalar_is_zero(&zero_scalar)))
        BIO_printf(io_print, "Overflow in scalar(0) || scalar(0) isnt 0.");
    // nonce = (scalar(0) + scalar(hash(bytes(private_key) || message))) mod group_order
    secp256k1_scalar_add(&nonce, &zero_scalar, &hashed_scalar);
    // nonce == 0 
    if(secp256k1_scalar_is_zero(&nonce))
        BIO_printf(io_print, "nonce equals 0");
    // R = nonce G


    secp256k1_scalar_set_int(&hashed_scalar, nonce_int);
    secp256k1_scalar_set_int(&nonce, nonce_int);
    printf("\nhashed_scalar = %d\n", hashed_int);
    printf("\nnonce = %d\n", nonce_int);

    // Liberando os ponteiros alocados
    EVP_cleanup();
    free(private_key);
    EC_KEY_free(elliptic_curve);
    BIO_free_all(io_print);

    exit(0);
}
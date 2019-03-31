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

#include <inttypes.h>

// Curva eliptica utilizada na criptografia de chave publica do Bitcoin
#define DEFAULT_ELLIPTIC_CURVE "secp256k1"

int main() {
            
    /**** generate_keys ****/
    BIO *io_print = NULL;                                                // Print OpenSSL
    EC_KEY *elliptic_curve = NULL;                                       // Curva eliptica OpenSSL

    int elliptic_curve_nid;                                              // Nome da curva eliptica OpenSSL
    unsigned char *private_key = calloc(1, sizeof(unsigned char));       // Chave privada em binario (32 bytes)

    secp256k1_context *ctx = calloc(1, sizeof(secp256k1_context));       // Contexto
    secp256k1_callback *cb = calloc(1, sizeof(secp256k1_callback));      // Callback para tratamento de erros
    secp256k1_pubkey *public_key = calloc(1, sizeof(secp256k1_pubkey));  // Chave publica em binario (64 bytes)

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
    if (!(secp256k1_ec_pubkey_create(ctx, public_key, private_key)))
        BIO_printf(io_print, "Error generating the public key.");
    printf("\nChave publica em binario (unsigned char)[%lu]: %s\n", sizeof(public_key->data), public_key->data);

    /**** sign_schnorr ****/
    unsigned char *message = calloc(4, sizeof(unsigned char));
    unsigned char *private_key_message = calloc(8, sizeof(unsigned char));
    unsigned char *hashed = calloc(4, sizeof(unsigned char));
    unsigned char *R_binary = calloc(4, sizeof(unsigned char));

    secp256k1_sha256 *hash = calloc(1, sizeof(secp256k1_sha256));

    secp256k1_scalar *hashed_scalar = calloc(1, sizeof(secp256k1_scalar));
    secp256k1_scalar *zero_scalar = calloc(1, sizeof(secp256k1_scalar));
    secp256k1_scalar *nonce = calloc(1, sizeof(secp256k1_scalar));
    secp256k1_scalar *R = calloc(1, sizeof(secp256k1_scalar));

    secp256k1_gej *group_element_jacobian = calloc(1, sizeof(secp256k1_gej));

    /* Assinatura Schnorr - R */
    // Let nonce = (scalar(0) + scalar(hash(bytes(private_key) || message))) mod group_order
    //      Fail if nonce = 0.
    // Let R = nonce G.

    // private_key_message = bytes(private_key) || message
    message = "Charles Leclerc";
    strcat(private_key_message, private_key);
    strcat(private_key_message, message);
    printf("\nprivate_key_message (unsigned char)[%lu]: %s\n", 8 * sizeof(private_key_message), private_key_message);
    // hashed = hash(bytes(private_key) || message)
    secp256k1_sha256_initialize(hash);
    secp256k1_sha256_write(hash, private_key_message, 8 * sizeof(private_key_message));
    secp256k1_sha256_finalize(hash, hashed);
    printf("\nhashed (unsigned char)[%lu]: %s\n", 4 * sizeof(hashed), hashed);

    // hashed_scalar = scalar(hash(bytes(private_key) || message))
    secp256k1_scalar_set_b32(hashed_scalar, hashed, NULL);
    printf("\nhashed_scalar: %" PRIu32 "\n", *hashed_scalar);
    // scalar(0)
    secp256k1_scalar_clear(zero_scalar);
    printf("\nzero_scalar: %" PRIu32 "\n", *zero_scalar);
    // nonce = (scalar(0) + scalar(hash(bytes(private_key) || message))) mod group_order
    secp256k1_scalar_add(nonce, hashed_scalar, zero_scalar);
    printf("\nnonce: %" PRIu32 "\n", *nonce);
    
    // R = nonce G
    R = nonce;
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, group_element_jacobian, R);
    if(secp256k1_scalar_is_zero(R))
        BIO_printf(io_print, "R equals 0");
    secp256k1_scalar_get_b32(R_binary, R);
    printf("\nR (unsigned char)[%lu]: %s\n", 4 * sizeof(R_binary), R_binary);

    // Liberando os ponteiros alocados

    exit(0);
}
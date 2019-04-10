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
    unsigned char *private_key;                                          // Chave privada em binario (32 bytes)

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
    private_key = calloc(1, BN_num_bytes(private_key_bignum));
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
    unsigned char *message = calloc(32, sizeof(unsigned char));                  // Mensagem de ate 32 bytes
    unsigned char *private_key_message = calloc(64, sizeof(unsigned char));      // Chave privada concatenada com a mensagem de ate 64 bytes
    unsigned char *hashed = calloc(32, sizeof(unsigned char));                   // Mensagem hasheada de 32 bytes

    unsigned char *group_order_bin = calloc(32, sizeof(unsigned char));          // Curve order em binario de 32 bytes

    unsigned char *yR = calloc(32, sizeof(unsigned char));                       // Coordenada afim Y do ponto R em 32 bytes
    unsigned char *xR = calloc(32, sizeof(unsigned char));                       // Coordenada afim X do ponto R em 32 bytes
    unsigned char *xR_public_key_message = calloc(128, sizeof(unsigned char));   // Coordenada afim X do ponto R concatenada com a chave publica e com a mensagem em 128 bytes
    unsigned char *hashed2 = calloc(32, sizeof(unsigned char));                  // Mensagem hasheada de 32 bytes

    unsigned char *k_bin = calloc(32, sizeof(unsigned char));                    // k de 32 bytes

    unsigned char *s = calloc(32, sizeof(unsigned char));                        // s de 32 bytes

    unsigned char *sign = calloc(64, sizeof(unsigned char));                     // Assinatura de 64 bytes

    secp256k1_sha256 *hash = calloc(1, sizeof(secp256k1_sha256));                // Hash SHA256 utilizado pelo Bitcoin

    secp256k1_scalar *nonce = calloc(1, sizeof(secp256k1_scalar));               // Random nonce
    secp256k1_scalar *R = calloc(1, sizeof(secp256k1_scalar));                   // R

    secp256k1_scalar *group_order_scalar = calloc(1, sizeof(secp256k1_scalar));  // Curve order em scalar

    secp256k1_scalar *k = calloc(1, sizeof(secp256k1_scalar));                   // k
    secp256k1_scalar *minus_nonce = calloc(1, sizeof(secp256k1_scalar));         // Complemento do random nonce

    secp256k1_scalar *e = calloc(1, sizeof(secp256k1_scalar));                   // e
    secp256k1_scalar *private_key_scalar = calloc(1, sizeof(secp256k1_scalar));  // Chave privada em scalar
    secp256k1_scalar *mul = calloc(1, sizeof(secp256k1_scalar));                 // Multiplicacao de dois scalars
    secp256k1_scalar *sum = calloc(1, sizeof(secp256k1_scalar));                 // Soma de dois scalar

    secp256k1_gej R_jacobian;                                                    // Ponto R jacobiano
    secp256k1_ge R_affine;                                                       // Ponto R afim

    secp256k1_num *group_order = calloc(1, sizeof(secp256k1_num));               // Curve order

    secp256k1_num *yR_num = calloc(1, sizeof(secp256k1_num));                    // Coordenada afim Y do ponto R em num
    secp256k1_num *k_num = calloc(1, sizeof(secp256k1_num));                     // k em num

    /* Assinatura Schnorr - R */
    // Let nonce = int(hash(bytes(private_key) || message)) mod group_order
    //      Fail if nonce = 0
    // Let R = nonce G.
    //
    // private_key_message = bytes(private_key) || message
    message = "Charles Leclerc";
    memcpy(private_key_message, private_key, 4 * sizeof(private_key));
    memcpy(private_key_message + (4 * sizeof(private_key)), message, 4 * sizeof(message));
    printf("\nprivate_key_message (unsigned char)[%lu]: %s\n", (4 * sizeof(private_key)) + (4 * sizeof(message)), private_key_message);
    // hashed = hash(bytes(private_key) || message)
    secp256k1_sha256_initialize(hash);
    secp256k1_sha256_write(hash, private_key_message, 8 * sizeof(private_key_message));
    secp256k1_sha256_finalize(hash, hashed);
    printf("\nhashed (unsigned char)[%lu]: %s\n", 4 * sizeof(hashed), hashed);
    // nonce = int(hash(bytes(private_key) || message)) mod group_order
    secp256k1_scalar_set_b32(nonce, hashed, NULL);
    printf("\nnonce (secp256k1_scalar): %" PRIu64 "\n", nonce->d[0]);
    printf("nonce (secp256k1_scalar): %" PRIu64 "\n", nonce->d[1]);
    printf("nonce (secp256k1_scalar): %" PRIu64 "\n", nonce->d[2]);
    printf("nonce (secp256k1_scalar): %" PRIu64 "\n", nonce->d[3]);
    // nonce == 0
    if (secp256k1_scalar_is_zero(nonce))
        BIO_printf(io_print, "Error nonce = 0.");
    // R = nonce G
    secp256k1_scalar_set_b32(R, hashed, NULL);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &R_jacobian, R);
    // Coordenadas jacobianas do ponto R para coordenadas afim do ponto R
    secp256k1_ge_set_gej(&R_affine, &R_jacobian);
    // Normalizacao das coordenadas afim do ponto R
    secp256k1_fe_normalize(&R_affine.y);
    secp256k1_fe_normalize(&R_affine.x);
    // Economia de um byte na assinatura (Omissao da coordenada Y do ponto R)
    if (secp256k1_fe_is_odd(&R_affine.y))
    {
        secp256k1_scalar_negate(nonce, nonce);
    }

    /* Assinatura Schnorr - s */
    // if jacobi(y(R)) = 1
    //      Let k = nonce
    // otherwise 
    //      Let k = group_order - nonce
    // Let e = int(hash(bytes(x(R)) || bytes(public_key) || message)) mod group_order
    // Let s = bytes(k + e private_key mod group_order).
    //
    // yR = bytes(y(R))
    secp256k1_fe_get_b32(yR, &R_affine.y);
    // yR_num = num(yR)
    secp256k1_num_set_bin(yR_num, yR, 4 * sizeof(yR));
    // group_order
    secp256k1_scalar_order_get_num(group_order);
    secp256k1_num_get_bin(group_order_bin, 4 * sizeof(group_order_bin), group_order);
    secp256k1_scalar_set_b32(group_order_scalar, group_order_bin, NULL);
    // if jacobi(y(R)) = 1
    if (secp256k1_num_jacobi(yR_num, group_order) == 1)
    {
        printf("\njacobi(y(R)) = 1\n");
        // k = int(nonce) mod group_order
        secp256k1_scalar_set_b32(k, hashed, NULL);
    }
    // otherwise
    else
    {
        printf("\njacobi(y(R)) != 1\n");
        // k = group_order - nonce
        secp256k1_scalar_negate(minus_nonce, nonce);
        secp256k1_scalar_add(k, group_order_scalar, minus_nonce);
    }
    printf("\nk (secp256k1_scalar): %" PRIu64 "\n", k->d[0]);
    printf("k (secp256k1_scalar): %" PRIu64 "\n", k->d[1]);
    printf("k (secp256k1_scalar): %" PRIu64 "\n", k->d[2]);
    printf("k (secp256k1_scalar): %" PRIu64 "\n", k->d[3]);
    // xR = bytes(x(R))
    secp256k1_fe_get_b32(xR, &R_affine.x);
    printf("\nxR (unsigned char)[%lu]: %s\n", 4 * sizeof(xR), xR);
    // xR_public_key_message = bytes(x(R)) || bytes(public_key) || message
    memcpy(xR_public_key_message, xR, 4 * sizeof(xR));
    memcpy(xR_public_key_message + (4 * sizeof(xR)), public_key->data, sizeof(public_key->data));
    memcpy(xR_public_key_message + (4 * sizeof(xR)) + sizeof(public_key->data), message, 4 * sizeof(message));
    printf("\nxR_public_key_message (unsigned char)[%lu]: %s\n", (4 * sizeof(xR)) + + sizeof(public_key->data) + (4 * sizeof(message)), xR_public_key_message);
    // hashed2 = hash(bytes(x(R)) || bytes(public_key) || message)
    secp256k1_sha256_initialize(hash);
    secp256k1_sha256_write(hash, xR_public_key_message, 16 * sizeof(xR_public_key_message));
    secp256k1_sha256_finalize(hash, hashed2);
    printf("\nhashed2 (unsigned char)[%lu]: %s\n", 4 * sizeof(hashed2), hashed2);
    // e = int(hash(bytes(x(R)) || bytes(public_key) || message)) mod group_order
    secp256k1_scalar_set_b32(e, hashed2, NULL);
    // private_key_scalar = int(private_key) mod group_order
    secp256k1_scalar_set_b32(private_key_scalar, private_key, NULL);
    // mul = e private_key mod group_order
    secp256k1_scalar_mul(mul, e, private_key_scalar);
    printf("\nmul (secp256k1_scalar): %" PRIu64 "\n", mul->d[0]);
    printf("mul (secp256k1_scalar): %" PRIu64 "\n", mul->d[1]);
    printf("mul (secp256k1_scalar): %" PRIu64 "\n", mul->d[2]);
    printf("mul (secp256k1_scalar): %" PRIu64 "\n", mul->d[3]);
    // sum = k + e secret_key mod group_order
    secp256k1_scalar_add(sum, k, mul);
    printf("\nsum (secp256k1_scalar): %" PRIu64 "\n", sum->d[0]);
    printf("sum (secp256k1_scalar): %" PRIu64 "\n", sum->d[1]);
    printf("sum (secp256k1_scalar): %" PRIu64 "\n", sum->d[2]);
    printf("sum (secp256k1_scalar): %" PRIu64 "\n", sum->d[3]);
    // s = bytes(sum) 
    secp256k1_scalar_get_b32(s, sum);
    printf("\ns (unsigned char)[%lu]: %s\n", 4 * sizeof(s), s);

    /* Assinatura Schnorr */
    // The signature is bytes(x(R)) || bytes(k + e secret_key mod group_order)
    memcpy(sign, xR, 4 * sizeof(xR));
    memcpy(sign + (4 * sizeof(xR)), s, 4 * sizeof(s));
    printf("\nsign (unsigned char)[%lu]: %s\n", (4 * sizeof(xR)) + (4 * sizeof(s)), sign);

    // Liberando os ponteiros alocados

    exit(0);
}
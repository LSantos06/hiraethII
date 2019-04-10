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
    /**** generate_keys ****/
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
    secp256k1_ecmult_context_init(&ctx->ecmult_ctx);
    secp256k1_ecmult_context_build(&ctx->ecmult_ctx, cb);

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
        BIO_printf(io_print, "ERROR generating public and private keys.");
    // Armazenamento da chave privada em bignum
    const BIGNUM *private_key_bignum = EC_KEY_get0_private_key(elliptic_curve);
    printf("Chave privada em BIGNUM: ");
    BN_print(io_print, private_key_bignum);
    printf("\n");
    // Chave privada em binario (32 bytes)
    private_key = calloc(1, BN_num_bytes(private_key_bignum));
    if (!(BN_bn2bin(private_key_bignum, private_key)))
        BIO_printf(io_print, "ERROR transforming private key to binary.");
    printf("\nChave privada em binario (unsigned char)[%d]: %s\n", BN_num_bytes(private_key_bignum), private_key);
    // Verificacao da validade da chave privada
    if (!(secp256k1_ec_seckey_verify(ctx, private_key)))
        BIO_printf(io_print, "ERROR validating the private key.");
    // Calculo da chave publica a partir da chave privada
    if (!(secp256k1_ec_pubkey_create(ctx, public_key, private_key)))
        BIO_printf(io_print, "ERROR generating the public key.");
    printf("\nChave publica em binario (unsigned char)[%lu]: %s\n", sizeof(public_key->data), public_key->data);

    /**** sign_schnorr ****/
    /**** sign_schnorr ****/
    /**** sign_schnorr ****/

    unsigned char *message = calloc(32, sizeof(unsigned char));                  // Mensagem de ate 32 bytes
    unsigned char *private_key_message = calloc(64, sizeof(unsigned char));      // Chave privada concatenada com a mensagem de ate 64 bytes
    unsigned char *hashed = calloc(32, sizeof(unsigned char));                   // Mensagem hasheada de 32 bytes

    unsigned char *group_order_bin = calloc(32, sizeof(unsigned char));          // Curve order em binario de 32 bytes

    unsigned char *yR = calloc(32, sizeof(unsigned char));                       // Coordenada afim Y do ponto R em 32 bytes
    unsigned char *xR = calloc(32, sizeof(unsigned char));                       // Coordenada afim X do ponto R em 32 bytes
    unsigned char *xR_public_key_message = calloc(128, sizeof(unsigned char));   // Coordenada afim X do ponto R concatenada com a chave publica e com a mensagem em 128 bytes

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

    int overflow = 0;

    /* Assinatura Schnorr - R */
    // Let nonce = int(hash(bytes(private_key) || message)) mod group_order
    //      Fail if nonce = 0.
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
    secp256k1_scalar_set_b32(nonce, hashed, &overflow);
    if (overflow)
        BIO_printf(io_print, "ERROR overflow nonce.");
    printf("\nnonce (secp256k1_scalar): %" PRIu64 "\n", nonce->d[0]);
    printf("nonce (secp256k1_scalar): %" PRIu64 "\n", nonce->d[1]);
    printf("nonce (secp256k1_scalar): %" PRIu64 "\n", nonce->d[2]);
    printf("nonce (secp256k1_scalar): %" PRIu64 "\n", nonce->d[3]);
    // nonce == 0
    if (secp256k1_scalar_is_zero(nonce))
        BIO_printf(io_print, "ERROR nonce = 0.");
    // R = nonce G
    secp256k1_scalar_set_b32(R, hashed, &overflow);
    if (overflow)
        BIO_printf(io_print, "ERROR overflow R.");
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
    //      Let k = nonce.
    // otherwise 
    //      Let k = group_order - nonce.
    // Let e = int(hash(bytes(x(R)) || bytes(public_key) || message)) mod group_order.
    // Let s = bytes(k + e private_key mod group_order).
    //
    // yR = bytes(y(R))
    secp256k1_fe_get_b32(yR, &R_affine.y);
    // yR_num = num(yR)
    secp256k1_num_set_bin(yR_num, yR, 4 * sizeof(yR));
    // group_order
    secp256k1_scalar_order_get_num(group_order);
    secp256k1_num_get_bin(group_order_bin, 4 * sizeof(group_order_bin), group_order);
    secp256k1_scalar_set_b32(group_order_scalar, group_order_bin, &overflow);
    if (overflow)
        BIO_printf(io_print, "ERROR overflow group_order_scalar.");
    // if jacobi(y(R)) = 1
    if (secp256k1_num_jacobi(yR_num, group_order) == 1)
    {
        printf("\njacobi(y(R)) = 1\n");
        // k = int(nonce) mod group_order
        secp256k1_scalar_set_b32(k, hashed, &overflow);
        if (overflow)
            BIO_printf(io_print, "ERROR overflow k.");
    }
    // otherwise
    else
    {
        printf("\njacobi(y(R)) != 1\n");
        // k = group_order - nonce
        secp256k1_scalar_negate(minus_nonce, nonce);
        if(secp256k1_scalar_add(k, group_order_scalar, minus_nonce))
            BIO_printf(io_print, "ERROR overflow k.");
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
    printf("\nxR_public_key_message (unsigned char)[%lu]: %s\n", (4 * sizeof(xR)) + sizeof(public_key->data) + (4 * sizeof(message)), xR_public_key_message);
    // hashed = hash(bytes(x(R)) || bytes(public_key) || message)
    secp256k1_sha256_initialize(hash);
    secp256k1_sha256_write(hash, xR_public_key_message, 16 * sizeof(xR_public_key_message));
    secp256k1_sha256_finalize(hash, hashed);
    printf("\nhashed2 (unsigned char)[%lu]: %s\n", 4 * sizeof(hashed), hashed);
    // e = int(hash(bytes(x(R)) || bytes(public_key) || message)) mod group_order
    secp256k1_scalar_set_b32(e, hashed, &overflow);
    if (overflow)
        BIO_printf(io_print, "ERROR overflow e.");
    // private_key_scalar = int(private_key) mod group_order
    secp256k1_scalar_set_b32(private_key_scalar, private_key, NULL);
    if (overflow)
        BIO_printf(io_print, "ERROR overflow private_key_scalar.");
    // mul = e private_key mod group_order
    secp256k1_scalar_mul(mul, e, private_key_scalar);
    printf("\nmul (secp256k1_scalar): %" PRIu64 "\n", mul->d[0]);
    printf("mul (secp256k1_scalar): %" PRIu64 "\n", mul->d[1]);
    printf("mul (secp256k1_scalar): %" PRIu64 "\n", mul->d[2]);
    printf("mul (secp256k1_scalar): %" PRIu64 "\n", mul->d[3]);
    // sum = k + e secret_key mod group_order
    if (secp256k1_scalar_add(sum, k, mul))
        BIO_printf(io_print, "ERROR overflow sum.");
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

    /**** verify_schnorr ****/
    /**** verify_schnorr ****/
    /**** verify_schnorr ****/

    unsigned char *compressed_public_key = calloc(33, sizeof(unsigned char));
    const unsigned char field_size[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 
                                          0xFC, 0x2F};
    const unsigned char group_order_teste[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
                                                 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 
                                                 0x41, 0x41};

    unsigned char *r = calloc(32, sizeof(unsigned char));                       

    unsigned char *r_P_message = calloc(97, sizeof(unsigned char));

    size_t compressed_public_key_size = 33;

    secp256k1_ge P_affine;
    secp256k1_gej P_jacobian;

    int compare;

    // Let P = point(public_key) 
    //      Fail if point(public_key) fails.
    // Let r = int(sign[0:32])
    //      Fail if r ≥ field_size.
    // Let s = int(sign[32:64])
    //      Fail if s ≥ group_order.
    // Let e = int(hash(bytes(r) || bytes(P) || message)) mod group_order.
    // Let R = s G - e P.
    //      Fail if infinite(R) 
    //      Fail if jacobi(y(R)) ≠ 1
    //      Fail if x(R) ≠ r.
    //
    // Verificacao da memoria group_order
    compare = memcmp(group_order_teste, group_order_bin, 32);
    if (compare != 0)
        BIO_printf(io_print, "ERROR group_order.");
    // Obtem a parte r da assinatura
    memcpy(r, xR, 4 * sizeof(xR));
    // Comprime a chave publica para o tamanho de 33 bytes
    secp256k1_ec_pubkey_serialize(ctx, compressed_public_key, &compressed_public_key_size, public_key, SECP256K1_EC_COMPRESSED);
    printf("\ncompressed_public_key (unsigned char)[%d]: %s\n", 33, compressed_public_key);
    // P = point(public_key) 
    //      Fail if point(public_key) fails.
    if (!(secp256k1_eckey_pubkey_parse(&P_affine, compressed_public_key, compressed_public_key_size)))
        BIO_printf(io_print, "ERROR generating public key point.");
    // r = int(sign[0:32])
    //      Fail if r ≥ field_size.
    compare = memcmp(r, field_size, 32);
    if (compare > 0 || compare == 0)
        BIO_printf(io_print, "ERROR r ≥ field_size.");
    // s = int(sign[32:64])
    //      Fail if s ≥ group_order.
    compare = memcmp(s, group_order_teste, 32);
    if (compare > 0 || compare == 0)
        BIO_printf(io_print, "ERROR s ≥ group_order.");
    // r_P_message = bytes(r) || bytes(P) || message
    memcpy(r_P_message, r, 4 * sizeof(r));
    memcpy(r_P_message + (4 * sizeof(r)), compressed_public_key, 33);
    memcpy(r_P_message + (4 * sizeof(r)) + 33, message, (4 * sizeof(message)));
    printf("\nr_P_message (unsigned char)[%lu]: %s\n", (4 * sizeof(r)) + 33 + (4 * sizeof(message)), r_P_message);
    // hashed = hash(bytes(r) || bytes(P) || message)
    secp256k1_sha256_initialize(hash);
    secp256k1_sha256_write(hash, r_P_message, 97);
    secp256k1_sha256_finalize(hash, hashed);
    printf("\nhashed3 (unsigned char)[%lu]: %s\n", 4 * sizeof(hashed), hashed);
    // e = int(hash(bytes(r) || bytes(P) || message)) mod group_order
    secp256k1_scalar_set_b32(e, hashed, &overflow);
    if (overflow)
        BIO_printf(io_print, "ERROR overflow e.");
    // e = -e
    secp256k1_scalar_negate(e, e);
    // Coordenadas afim do ponto P para coordenadas jacobianas do ponto P
    secp256k1_gej_set_ge(&P_jacobian, &P_affine);
    // R = - e P + s G
    //      Fail if infinite(R) 
    //      Fail if jacobi(y(R)) ≠ 1
    //      Fail if x(R) ≠ r.
    secp256k1_ecmult(&ctx->ecmult_ctx, &R_jacobian, &P_jacobian, e, sum);
    // Coordenadas jacobianas do ponto R para coordenadas afim do ponto R
    secp256k1_ge_set_gej(&R_affine, &R_jacobian);
    // Normalizacao das coordenadas afim do ponto R
    secp256k1_fe_normalize(&R_affine.y);
    secp256k1_fe_normalize(&R_affine.x);
    //      Fail if infinite(R) 
    if (secp256k1_gej_is_infinity(&R_jacobian) || secp256k1_ge_is_infinity(&R_affine))
        BIO_printf(io_print, "ERROR R is infinity.");
    //      Fail if jacobi(y(R)) ≠ 1
    // yR = bytes(y(R))
    secp256k1_fe_get_b32(yR, &R_affine.y);
    // yR_num = num(yR)
    secp256k1_num_set_bin(yR_num, yR, 4 * sizeof(yR));
    if (secp256k1_num_jacobi(yR_num, group_order) != 1)
        BIO_printf(io_print, "ERROR jacobi(y(R)) ≠ 1.");
    //      Fail if x(R) ≠ r.
    // xR = bytes(x(R))
    secp256k1_fe_get_b32(xR, &R_affine.x);
    compare = memcmp(xR, r, 32);
    if (compare != 0)
        BIO_printf(io_print, "ERROR x(R) ≠ r.");

    // Liberando os ponteiros alocados

    exit(0);
}
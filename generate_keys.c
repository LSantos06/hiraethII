/* OpenSSL */
// Biblioteca de IO
#include <openssl/bio.h>
// Biblioteca de erros
#include <openssl/err.h>
// Biblioteca de curva eliptica
#include <openssl/ec.h>
// Biblioteca para tratamendo de BIGNUM
#include <openssl/bn.h>
// Biblioteca para formatação de chaves
#include <openssl/pem.h>

/* secp256k1 */
// Biblioteca de curva eliptica
#include "../secp256k1/include/secp256k1.h"

// Curva eliptica utilizada na criptografia de chave publica do Bitcoin
#define DEFAULT_ELLIPTIC_CURVE "secp256k1"

int main() {
             
    secp256k1_context *ctx = NULL;
    BIO *io_print = NULL;
    EC_KEY *elliptic_curve = NULL;
    unsigned char *private_key_bin = NULL;
    secp256k1_pubkey *public_key = NULL;
    EVP_PKEY *keys = NULL;
    int elliptic_curve_nid;

    /* Inicializacao da biblioteca OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* Inicializacao da biblioteca secp256k1 */
    ctx = secp256k1_context_create(SECP256K1_FLAGS_TYPE_CONTEXT);

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
    // Armazenamento da chave privada
    const BIGNUM *private_key = EC_KEY_get0_private_key(elliptic_curve);
    BN_print(io_print, private_key);
    // Chave privada em binario (32 bytes)
    private_key_bin = malloc(BN_num_bytes(private_key));
    if (!(BN_bn2bin(private_key, private_key_bin)))
        BIO_printf(io_print, "Error transforming private key to binary.");
    printf("\n%s", private_key_bin);
    // Calculo da chave publica a partir da chave privada
    if (!(secp256k1_ec_pubkey_create(ctx, public_key, private_key_bin)))
        BIO_printf(io_print, "Error generating the public key.");
    printf("\n%s", public_key->data);

    /* Infos da curva eliptica */
    // Estrutura PEM utilizada para armazenas as chaves
    keys = EVP_PKEY_new();
    // Armazena as chaves geradas na estrutura PEM
    if (!EVP_PKEY_assign_EC_KEY(keys, elliptic_curve))
        BIO_printf(io_print, "Error when saving public and private keys.");
    // Obtem a curva eliptica a partir da estrutura PEM
    elliptic_curve = EVP_PKEY_get1_EC_KEY(keys);
    // Obtem o grupo da curva eliptica
    const EC_GROUP *elliptic_curve_group = EC_KEY_get0_group(elliptic_curve);
    // Imprime na tela o tamanho das chaves
    BIO_printf(io_print, "\nKey size: %d bits\n", EVP_PKEY_bits(keys));
    // Tipo da curva eliptica utilizada
    BIO_printf(io_print, "Elliptic Curve: %s\n", OBJ_nid2ln(EC_GROUP_get_curve_name(elliptic_curve_group)));

    // Liberando os ponteiros alocados
    EVP_PKEY_free(keys);
    free(private_key_bin);
    EC_KEY_free(elliptic_curve);
    BIO_free_all(io_print);

    exit(0);
}
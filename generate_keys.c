/* Bibliotecas */
// Biblioteca de IO
#include <openssl/bio.h>
// Biblioteca de erros
#include <openssl/err.h>
// Biblioteca de curva eliptica
#include <openssl/ec.h>
// Biblioteca com o formato das chaves
#include <openssl/pem.h>

// Curva eliptica utilizada na criptografia de chave publica do Bitcoin
#define DEFAULT_ELLIPTIC_CURVE "secp256k1"

int main() {
             
    BIO *io_print = NULL;
    //BIO *io_file = NULL;
    EC_KEY *elliptic_curve = NULL;
    EVP_PKEY *keys = NULL;
    int elliptic_curve_nid;

    /* Inicializacao da biblioteca OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

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
    // Estrutura utilizada para armazenas as chaves
    keys = EVP_PKEY_new();
    // Armazena as chaves geradas na estrutura 
    if (!EVP_PKEY_assign_EC_KEY(keys, elliptic_curve))
        BIO_printf(io_print, "Error when saving public and private keys.");

    /* Infos da curva eliptica */
    // Obtem a curva eliptica a partir da estrutura
    elliptic_curve = EVP_PKEY_get1_EC_KEY(keys);
    // Obtem o grupo da curva eliptica
    const EC_GROUP *elliptic_curve_group = EC_KEY_get0_group(elliptic_curve);
    // Imprime na tela o tamanho das chaves
    BIO_printf(io_print, "Keys size: %d bits\n", EVP_PKEY_bits(keys));
    // Tipo da curva eliptica utilizada
    BIO_printf(io_print, "Elliptic Curve type: %s\n", OBJ_nid2ln(EC_GROUP_get_curve_name(elliptic_curve_group)));

    /* Impressao das chaves */
    // Impressao completa da chave privada
    if(!PEM_write_bio_PKCS8PrivateKey(io_print, keys, NULL, NULL, 0, 0, NULL))
        BIO_printf(io_print, "Error printing private key in PEM format");
    // Impressao da chave publica no formato SubjectPublicKeyInfo
    if(!PEM_write_bio_PUBKEY(io_print, keys))
        BIO_printf(io_print, "Error printing public key in PEM format");

    // Liberando os ponteiros alocados
    EVP_PKEY_free(keys);
    EC_KEY_free(elliptic_curve);
    BIO_free_all(io_print);

    exit(0);
}
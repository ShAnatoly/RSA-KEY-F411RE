#include "rsa.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "asn1.h"
#include "base64.h"
#include "bignum.h"
#include "montgomery.h"

void import_pub_key(rsa_pub_key_t *key, const char *data) {
    const char begin[] = "-----BEGIN PUBLIC KEY-----";
    const char end[] = "-----END PUBLIC KEY-----";
    size_t in_size = 2048;
    char pem[in_size];
    strcpy(pem, data);

    size_t beg_size = strlen(begin);
    size_t end_size = strlen(end);
    size_t pem_size = strlen(pem);
    char *beg_pos = strstr(pem, begin);
    size_t beg_idx = beg_pos - pem;
    char *end_pos = strstr(pem, end);
    size_t end_idx = end_pos - pem;

    if (beg_idx == 0 && end_idx == pem_size - end_size) {
        const uint8_t *int_ptr;
        size_t int_size;
        uint8_t *read_ptr;
        size_t read_size;
        uint8_t buffer[in_size];
        memset(buffer, 0, in_size);

        base64_read((uint8_t *)data + beg_size, pem_size - beg_size - end_size, buffer, in_size);

        const size_t key_padding = asn1_get_padding_pub_key(buffer);
        read_ptr = buffer + key_padding;

        read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
        if (read_size == -1) {
            return;
        }
        bn_from_bytes(&key->mod, int_ptr, int_size);
        read_ptr += read_size;

        read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
        if (read_size == -1) {
            return;
        }
        bn_from_bytes(&key->pub_exp, int_ptr, int_size);
        read_ptr += read_size;
    }
}

void import_pvt_key(rsa_pvt_key_t *key, const char *data) {
    const char begin[] = "-----BEGIN PRIVATE KEY-----";
    const char end[] = "-----END PRIVATE KEY-----";
    size_t in_size = 9192;
    char pem[in_size];
    strcpy(pem, data);

    size_t beg_size = strlen(begin);
    size_t end_size = strlen(end);
    size_t pem_size = strlen(pem);
    char *beg_pos = strstr(pem, begin);
    size_t beg_idx = beg_pos - pem;
    char *end_pos = strstr(pem, end);
    size_t end_idx = end_pos - pem;

    if (!(beg_idx == 0 && end_idx == pem_size - end_size)) {
        return;
    }
    
    const uint8_t *int_ptr;
    size_t int_size;
    uint8_t *read_ptr;
    size_t read_size;
    uint8_t buffer[in_size];
    memset(buffer, 0, in_size);

    base64_read((uint8_t *)data + beg_size, pem_size - beg_size - end_size, buffer, in_size);

    const size_t key_padding = asn1_get_padding_pvt_key(buffer);
    read_ptr = buffer + key_padding;
    read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
    if (read_size == -1) {
        return;
    }

    bignum_t version;
    bn_from_bytes(&version, int_ptr, int_size);
    if (!bn_is_zero(&version, BN_ARRAY_SIZE)) {
        return;
    }
    read_ptr += read_size;

    bignum_t *targets[] = {&key->mod, &key->pub_exp, &key->pvt_exp, &key->p, &key->q, &key->exp1, &key->exp2, &key->coeff};
    size_t targets_size = sizeof(targets) / sizeof(bignum_t *);
    for (size_t i = 0; i < targets_size; i++) {
        read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
        if (read_size == -1) {
            return;
        }
        bn_from_bytes(targets[i], int_ptr, int_size);
        read_ptr += read_size;
    }
}

static void encrypt(const rsa_pub_key_t *key, const montg_t *montg_domain, const bignum_t *bignum_in, bignum_t *bignum_out) {
    bignum_t bignum_montg_in, bignum_montg_out;

    montg_transform(montg_domain, bignum_in, &bignum_montg_in);
    bn_init(&bignum_montg_out, BN_ARRAY_SIZE);

    montg_pow(montg_domain, &bignum_montg_in, &key->pub_exp, &bignum_montg_out);
    montg_revert(montg_domain, &bignum_montg_out, bignum_out);
}

void encrypt_buf(const rsa_pub_key_t *key, const montg_t *montg_domain, const char *buffer_in, size_t bignum_in_len, char *buffer_out, size_t bignum_out_len) {
    bignum_t in_bn, out_bn;
    bn_init(&in_bn, BN_ARRAY_SIZE);

    memmove(in_bn, buffer_in, bignum_in_len * sizeof(char));
    encrypt(key, montg_domain, &in_bn, &out_bn);
    bn_to_string(&out_bn, buffer_out, bignum_out_len);
}

static void decrypt(const rsa_pvt_key_t *key, const montg_t *montg_domain, const bignum_t *bignum_in, bignum_t *bignum_out) {
    bignum_t bignum_montg_in, bignum_montg_out;

    montg_transform(montg_domain, bignum_in, &bignum_montg_in);
    bn_init(&bignum_montg_out, BN_ARRAY_SIZE);
    montg_pow(montg_domain, &bignum_montg_in, &key->pvt_exp, &bignum_montg_out);
    montg_revert(montg_domain, &bignum_montg_out, bignum_out);
}

void decrypt_buf(const rsa_pvt_key_t *key, const montg_t *montg_domain, const char *buffer_in, size_t buffer_in_len, char *buffer_out, size_t buffer_out_len) {
    bignum_t in_bn, out_bn;
    bn_init(&in_bn, BN_ARRAY_SIZE);

    bn_from_string(&in_bn, buffer_in, buffer_in_len);
    decrypt(key, montg_domain, &in_bn, &out_bn);
    memmove(buffer_out, out_bn, buffer_out_len * sizeof(uint8_t));
}

void sign_buf(const rsa_pvt_key_t *key, const montg_t *montg_domain, const char *buffer_in, size_t buffer_in_len, char *buffer_out, size_t buffer_out_len) {
    bignum_t in_bn = {0}, out_bn;

    memmove(in_bn, buffer_in, buffer_in_len * sizeof(char));
    decrypt(key, montg_domain, &in_bn, &out_bn);
    bn_to_string(&out_bn, buffer_out, buffer_out_len);
}

void verify_buf(const rsa_pub_key_t *key, const montg_t *montg_domain, const char *buffer_in, size_t bignum_in_len, char *buffer_out, size_t bignum_out_len) {
    bignum_t in_bn = {0}, out_bn;

    bn_from_string(&in_bn, buffer_in, bignum_in_len);
    encrypt(key, montg_domain, &in_bn, &out_bn);
    memmove(buffer_out, out_bn, bignum_out_len * sizeof(uint8_t));
}
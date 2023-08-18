#include "common.h"

enum crypto_error crypto42_errno = CRYPTO_SUCCESS;

const char       *crypto42_strerror(enum crypto_error err) {
    switch (err) {
    case CRYPTO_CTX_NULL:
        return "Context is NULL";
    case CRYPTO_KEY_NULL:
        return "Key is NULL";
    case CRYPTO_KEY_LEN_ZERO:
        return "Key length is zero";
    case CRYPTO_PLAINTEXT_NULL:
        return "Plaintext is NULL";
    case CRYPTO_PLAINTEXT_LEN_ZERO:
        return "Plaintext length is zero";
    case CRYPTO_CIPHERTEXT_NULL:
        return "Ciphertext is NULL";
    case CRYPTO_CIPHERTEXT_LEN_ZERO:
        return "Ciphertext length is zero";
    case CRYPTO_IV_NULL:
        return "IV is NULL";
    case CRYPTO_IV_LEN_ZERO:
        return "IV length is zero";
    case CRYPTO_NONCE_NULL:
        return "Nonce is NULL";
    case CRYPTO_NONCE_LEN_ZERO:
        return "Nonce length is zero";
    case CRYPTO_BLKSIZE_ZERO:
        return "Block size is zero";
    case CRYPTO_BLKSIZE_INVALID:
        return "Block size must be either 8 or 16";
    case CRYPTO_CIPHERTEXT_BLKSIZE_UNMATCH:
        return "Ciphertext should be a multiple of the block size";
    case CRYPTO_IV_BLKSIZE_UNMATCH:
        return "IV should be equal to the block size";
    case CRYPTO_ALGO_UNKNOWN:
        return "Unknown algorithm";
    case CRYPTO_ALGO_INVALID_BLKSIZE:
        return "Invalid block size for the algorithm";
    case CRYPTO_SUCCESS:
        return "Success";
    case CRYPTO_NONCE_BLKSIZE_UNMATCH:
        return "Nonce should be equal to the block size";
    default:
        return "Unknown error";
    }
}

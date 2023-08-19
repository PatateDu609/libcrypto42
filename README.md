# libcrypto42

![Badge workflow](https://github.com/PatateDu609/libcrypto42/actions/workflows/tests.yml/badge.svg)

## Description

This is a small library designed to work with the 42 projects that would need to use some cryptographic functions.

## Dependencies

+ make (version 4.3 or greater)
+ gcc (version 13.1.1 or greater)
+ The bundled libft (another library that I created in the context of 42)
+ libm

And the following libraries (to build and run tests):

+ Google test which is declared as a submodule of this repos (it will be pulled and built by the Makefile)
+ openssl itself to use its library

## How to use it

```bash
$ make # compile only libcrypto42
$ make check # run tests
```

To compile an executable using this library, you need to add the following libraries:

+ `libcrypto42.a` (`-L<path to libcrypto42> -lcrypto42`)
+ `libft.a` (`-L<path to libft> -lft`)
+ The system math library (`-lm`)

## Progress

+ [x] MD5
+ [x] SHA2 suite (sha224, sha256, sha384, sha512, sha512/224, sha512/256)
+ [ ] SHA3 suite
+ [x] PBKDF
+ [x] HMAC
+ [x] DES
+ [x] AES
    + [x] AES128
    + [x] AES192
    + [x] AES256
+ [x] 3DES (EDE only)
    + [x] 2 Keys option
    + [x] 3 Keys option
+ [x] Operation modes for symmetric encryption
    + [x] ECB
    + [x] CBC
    + [x] CFB
    + [x] OFB
    + [x] CTR
+ [x] Base64
+ [x] Use of the Kernel CSPRNG

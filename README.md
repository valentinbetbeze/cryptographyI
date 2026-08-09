# cryptographyI

A personal project for learning applied cryptography through implementation, based on the Stanford course Cryptography I taught by Prof. Dan Boneh.

## Overview

This repository contains implementations of classical cryptographic algorithms written in C, along with test code and reference vectors. The goal of the project is **strictly educational**: understanding how cryptographic primitives work under the hood and why misusing them leads to security vulnerabilities.

The code in this repository is not intended to be production-grade cryptographic software and should **not be used for security-critical applications**.

> [!NOTE]
> Cryptography is easy to misuse. Real-world applications should rely on well-reviewed libraries such as OpenSSL or libsodium rather than custom implementations.

## Getting Started

Install the following:
* cmake >= 3.22.1
* gcc >= 15.2.1
* ninja >= 1.12.1
* libcurl4-openssl-dev >= 7.81.0
* libgmp-dev >= 6.3.0
* python >= 3.11.0

On Fedora/RHEL:
* libasan >= 8.0.0
* libubsan >= 1.0.0

Build with:
`cmake --preset gcc-release && cmake --build --preset gcc-release`

Then test against FIPS KAT with:
`ctest --preset gcc-test`

## Project Structure

```
.
├── crypto/     cryptographic primitive implementations
├── pa/         cryptography I course progamming assignments
├── tests/      NIST/FIPS Known Answer Test vectors
└── utils/      helper functions and utilities
```

## License

MIT

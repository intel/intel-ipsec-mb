# Intel(R) Multi-Buffer Crypto for IPsec Library - Fuzz Test Applications

## Contents

- Overview
- Dependencies
- Usage


## Overview

The fuzz test applications aim to discover defects in the library by passing
randomly generated data to the library API's. Currently there are two fuzzing
applications:
- imb-fuzz-direct-api: Targets direct API's
- imb-fuzz-api: Targets job and burst API's


## Dependencies
- clang
- libfuzzer

## Usage

Usage:
    `./imb-fuzz-api`
    `./imb-fuzz-direct-api`

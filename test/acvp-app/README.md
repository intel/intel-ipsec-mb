# Intel(R) Multi-Buffer Crypto for IPsec Library - ACVP Test Application

## Contents

- Overview
- Usage


## Overview

The [ACVP](https://pages.nist.gov/ACVP/draft-fussell-acvp-spec.html)
(Automated Cryptographic Validation Protocol) test application performs
validation of NIST-approved cryptographic algorithms as part of the
[CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
(Cryptographic Algorithm Validation Program).
[libacvp](https://github.com/cisco/libacvp) is used as the client-side implementation [ACVP protocol](github.com/usnistgov/ACVP).
See intel-ipsec-mb [README](https://github.com/intel/intel-ipsec-mb/blob/main/README.md#12-fips-compliance) for details about exercised algorithms and their parameters.

## Usage

Before running the application, ensure the library is installed by following the instructions
in the [README](https://github.com/intel/intel-ipsec-mb/tree/main/test#library-installation).
Installation of [libacvp](https://github.com/cisco/libacvp) is also required. Please follow its build and install instructions.
### Linux
To perform AES-GCM validation:  
`./imb-acvp --req AES-GCM-req.json --resp AES-GCM-resp.json`  

To perform AES-GCM validation for AVX512 architecture only:  
`./imb-acvp --req AES-GCM-req.json --resp AES-GCM-resp.json --arch AVX512`  

To display an extensive help page:  
`./imb-acvp --help` 

### Windows
Not currently supported.

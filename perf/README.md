# Intel(R) Multi-Buffer Crypto for IPsec Library - Performance Application

## Contents

- Overview
- Usage

## Overview
The performance application is used to measure the performance of all supported algorithms in the Intel(R) Multi-Buffer Crypto for IPsec Library.
The application accepts a user specified algorithm as an input, and outputs the number of CPU cycles taken to process a range of buffer sizes for that algorithm.
By default, all supported architectural implementations (e.g. SSE, AVX, AVX2 & AVX512) are exercised. 
The perf directory also contains scripts to add extra functionality to the application, and to post process the results.  

## Usage

### Performance Application
Before running the application, ensure the library is installed by following the instructions
in the [INSTALL](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#installation) file.  

To measure AES-GCM-128 encryption performance for all supported architectural implementations:  
`imb-perf --aead-algo aes-gcm-128 --cipher-dir encrypt > file.txt`  

To run AES-CBC-128 decryption 30,000 times on 16kB buffer exercising the AVX512 implementation:  
`imb-perf --cipher-algo aes-cbc-128 --cipher-dir decrypt --arch AVX512 --job-size 16384 --job-iter 30000 > file.txt`  

To measure AES-CBC-128 encryption with HMAC-SHA1 using the best available architectural implementation:  
`imb-perf --cipher-algo aes-cbc-128 --hash-algo sha1-hmac --arch-best > file.txt`  

To print system and available algorithms:  
`imb-perf --print-info`  

For more options:  
`imb-perf --help`  

### Post Processing

The `ipsec_diff_tool.py` can be used to transform the output of the performance application into more human readable formats.  

To compare two result files:  
`ipsec_diff_tool.py file_1.txt file_2.txt`  

To display results in the form of a linear equation (slope & intercept):  
`ipsec_diff_tool.py -a file_1.txt`  

To pass packet size and clock speed as arguments and calculate throughput in Mbps:  
 `ipsec_diff_tool.py -t 512 2200 file_1.txt file_2.txt`  

For more information:  
`ipsec_perf_tool.py -h`  


### Running the ipsec_perf_tool.py script

The performance application supports benchmarking specific algorithms **_only_**. To benchmark multiple algorithms, the `ipsec_perf_tool.py` script should be used.
This acts as a wrapper script around the updated `imb-perf` tool to provide extra functionality while maintaining compatibility with the `ipsec_diff_tool.py` to parse and display results.

To benchmark all cipher, hash and AEAD algorithms on all available architectures:   
`ipsec_perf_tool.py > file.txt`  

To benchmark all cipher algorithms in encrypt direction using SSE and AVX architectures:  
`ipsec_perf_tool.py -t cipher-only -d encrypt -a SSE -a AVX > file.txt`  

To benchmark all cipher-hash combinations using AVX512 architecture:  
`ipsec_perf_tool.py -t cipher-hash-all -a AVX512 > file.txt`  

To distribute algorithm benchmarks across a range of cores from 2 to 10:  
`ipsec_perf_tool.py -c 2-10 > file.txt`  

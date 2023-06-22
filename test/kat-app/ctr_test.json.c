/*****************************************************************************
 Copyright (c) 2023, Intel Corporation

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

/* CTR, RFC3686 */
#include "cipher_test.h"
const struct cipher_test ctr_test_json[] = {
        /* Vectors from https://tools.ietf.org/html/rfc3686 */
        {96, 128, 1,
         "\xae\x68\x52\xf8\x12\x10\x67\xcc\x4b\xf7\xa5\x76\x55\x77\xf3\x9e",
         "\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00",
         "\x53\x69\x6e\x67\x6c\x65\x20\x62\x6c\x6f\x63\x6b\x20\x6d\x73\x67",
         "\xe4\x09\x5d\x4f\xb7\xa7\xb3\x79\x2d\x61\x75\xa3\x26\x13\x11\xb8", 1,
         128},
        {96, 128, 2,
         "\x7e\x24\x06\x78\x17\xfa\xe0\xd7\x43\xd6\xce\x1f\x32\x53\x91\x63",
         "\x00\x6c\xb6\xdb\xc0\x54\x3b\x59\xda\x48\xd9\x0b",
         "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"
         "\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
         "\x51\x04\xa1\x06\x16\x8a\x72\xd9\x79\x0d\x41\xee\x8e\xda\xd3\x88\xeb\x2e"
         "\x1e\xfc\x46\xda\x57\xc8\xfc\xe6\x30\xdf\x91\x41\xbe\x28",
         1, 256},
        {96, 128, 3,
         "\x76\x91\xbe\x03\x5e\x50\x20\xa8\xac\x6e\x61\x85\x29\xf9\xa0\xdc",
         "\x00\xe0\x01\x7b\x27\x77\x7f\x3f\x4a\x17\x86\xf0",
         "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"
         "\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23",
         "\xc1\xcf\x48\xa8\x9f\x2f\xfd\xd9\xcf\x46\x52\xe9\xef\xdb\x72\xd7\x45\x40"
         "\xa4\x2b\xde\x6d\x78\x36\xd5\x9a\x5c\xea\xae\xf3\x10\x53\x25\xb2\x07\x2f",
         1, 288},
        {96, 192, 4,
         "\x16\xaf\x5b\x14\x5f\xc9\xf5\x79\xc1\x75\xf9\x3e\x3b\xfb\x0e\xed\x86\x3d"
         "\x06\xcc\xfd\xb7\x85\x15",
         "\x00\x00\x00\x48\x36\x73\x3c\x14\x7d\x6d\x93\xcb",
         "\x53\x69\x6e\x67\x6c\x65\x20\x62\x6c\x6f\x63\x6b\x20\x6d\x73\x67",
         "\x4b\x55\x38\x4f\xe2\x59\xc9\xc8\x4e\x79\x35\xa0\x03\xcb\xe9\x28", 1,
         128},
        {96, 192, 5,
         "\x7c\x5c\xb2\x40\x1b\x3d\xc3\x3c\x19\xe7\x34\x08\x19\xe0\xf6\x9c\x67\x8c"
         "\x3d\xb8\xe6\xf6\xa9\x1a",
         "\x00\x96\xb0\x3b\x02\x0c\x6e\xad\xc2\xcb\x50\x0d",
         "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"
         "\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
         "\x45\x32\x43\xfc\x60\x9b\x23\x32\x7e\xdf\xaa\xfa\x71\x31\xcd\x9f\x84\x90"
         "\x70\x1c\x5a\xd4\xa7\x9c\xfc\x1f\xe0\xff\x42\xf4\xfb\x00",
         1, 256},
        {96, 192, 6,
         "\x02\xbf\x39\x1e\xe8\xec\xb1\x59\xb9\x59\x61\x7b\x09\x65\x27\x9b\xf5\x9b"
         "\x60\xa7\x86\xd3\xe0\xfe",
         "\x00\x07\xbd\xfd\x5c\xbd\x60\x27\x8d\xcc\x09\x12",
         "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"
         "\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23",
         "\x96\x89\x3f\xc5\x5e\x5c\x72\x2f\x54\x0b\x7d\xd1\xdd\xf7\xe7\x58\xd2\x88"
         "\xbc\x95\xc6\x91\x65\x88\x45\x36\xc8\x11\x66\x2f\x21\x88\xab\xee\x09\x35",
         1, 288},
        {96, 256, 7,
         "\x77\x6b\xef\xf2\x85\x1d\xb0\x6f\x4c\x8a\x05\x42\xc8\x69\x6f\x6c\x6a\x81"
         "\xaf\x1e\xec\x96\xb4\xd3\x7f\xc1\xd6\x89\xe6\xc1\xc1\x04",
         "\x00\x00\x00\x60\xdb\x56\x72\xc9\x7a\xa8\xf0\xb2",
         "\x53\x69\x6e\x67\x6c\x65\x20\x62\x6c\x6f\x63\x6b\x20\x6d\x73\x67",
         "\x14\x5a\xd0\x1d\xbf\x82\x4e\xc7\x56\x08\x63\xdc\x71\xe3\xe0\xc0", 1,
         128},
        {96, 256, 8,
         "\xf6\xd6\x6d\x6b\xd5\x2d\x59\xbb\x07\x96\x36\x58\x79\xef\xf8\x86\xc6\x6d"
         "\xd5\x1a\x5b\x6a\x99\x74\x4b\x50\x59\x0c\x87\xa2\x38\x84",
         "\x00\xfa\xac\x24\xc1\x58\x5e\xf1\x5a\x43\xd8\x75",
         "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"
         "\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
         "\xf0\x5e\x23\x1b\x38\x94\x61\x2c\x49\xee\x00\x0b\x80\x4e\xb2\xa9\xb8\x30"
         "\x6b\x50\x8f\x83\x9d\x6a\x55\x30\x83\x1d\x93\x44\xaf\x1c",
         1, 256},
        {96, 256, 9,
         "\xff\x7a\x61\x7c\xe6\x91\x48\xe4\xf1\x72\x6e\x2f\x43\x58\x1d\xe2\xaa\x62"
         "\xd9\xf8\x05\x53\x2e\xdf\xf1\xee\xd6\x87\xfb\x54\x15\x3d",
         "\x00\x1c\xc5\xb7\x51\xa5\x1d\x70\xa1\xc1\x11\x48",
         "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"
         "\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23",
         "\xeb\x6c\x52\x82\x1d\x0b\xbb\xf7\xce\x75\x94\x46\x2a\xca\x4f\xaa\xb4\x07"
         "\xdf\x86\x65\x69\xfd\x07\xf4\x8c\xc0\xb5\x83\xd6\x07\x1f\x1e\xc0\xe6\xb8",
         1, 288},
        {96, 128, 10,
         "\xae\x68\x52\xf8\x12\x10\x67\xcc\x4b\xf7\xa5\x76\x55\x77\xf3\x9e",
         "\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00",
         "\xa8\x63\x44\xf8\x36\x59\x2f\xf2\xda\xdd\x17\xce\xfe\x2a\xf2\xa2\x35\x87"
         "\x34\x0f\x35\xfc\xd8\xf2\x57\xa1\xcb\x19\x0c\x33\x14\xe1\x23\xeb\xc0\x88"
         "\x82\x05\x5f\x01\x5d\xfc\x53\x08\xdb\x34\x8e\x94\xe4\xa8\x26\x7f\xbc\xb7"
         "\x8b\xe1\x58\x2f\x2c\x91\xcd\x5b\x4a\xaa\x7a\xba\x5f\xd2\x9b\xf8\x7d\xea"
         "\x76\xb6\x64\xb3\x29\xd3\x02\x19\xa0\xdc\xe9\xb8\x90\x51\xa8\xde\x2e\xa1"
         "\xb7\x7e\x51\x0d\x34\xb3\xed\xe7\x5e\xb8\x8a\xe9\xfe\x89\xf8\x0b\x85\x09"
         "\x76\x08\x78\x0d\x27\x59\x8e\x14\x43\x46\xa0\x91\xee\xaa\xff\x74\x8d\xbc"
         "\x98\xb9",
         "\x1f\x03\x77\xd0\xed\x9b\xbc\xe9\x9b\xd3\x01\x06\xf8\x54\x90\x7d\x67\x6f"
         "\x19\xd7\x0b\xf3\x92\x8d\x60\xc0\x18\x5a\x24\xc1\xd7\x60\x82\x9c\x22\x37"
         "\x45\xe3\x9d\xa6\x76\x37\xe1\x7a\x13\xb4\x40\x63\xf4\xd8\xde\x41\x64\xfc"
         "\xe2\x42\x2e\x3f\xea\xe1\x28\x06\xa5\xac\x6a\xc1\x58\x0c\x84\xff\x9b\x6a"
         "\xe5\xbe\x4e\x8c\x4c\xe9\x97\xd5\x24\x30\x1b\x19\xdf\x87\x56\x85\x31\x56"
         "\x5a\xde\xe0\x6e\xc0\x1c\xcb\x51\x5b\x6e\xac\xf5\xb0\x60\x60\x2f\x62\x0a"
         "\xea\x62\x51\x2e\x5b\x1b\x99\x51\x3b\xac\xe9\xc5\x59\x7d\x0e\xb6\x51\x6c"
         "\x16\x7a",
         1, 1024},
        {96, 128, 11,
         "\xae\x68\x52\xf8\x12\x10\x67\xcc\x4b\xf7\xa5\x76\x55\x77\xf3\x9e",
         "\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00",
         "\xa8\x63\x44\xf8\x36\x59\x2f\xf2\xda\xdd\x17\xce\xfe\x2a\xf2\xa2\x35\x87"
         "\x34\x0f\x35\xfc\xd8\xf2\x57\xa1\xcb\x19\x0c\x33\x14\xe1\x23\xeb\xc0\x88"
         "\x82\x05\x5f\x01\x5d\xfc\x53\x08\xdb\x34\x8e\x94\xe4\xa8\x26\x7f\xbc\xb7"
         "\x8b\xe1\x58\x2f\x2c\x91\xcd\x5b\x4a\xaa\x7a\xba\x5f\xd2\x9b\xf8\x7d\xea"
         "\x76\xb6\x64\xb3\x29\xd3\x02\x19\xa0\xdc\xe9\xb8\x90\x51\xa8\xde\x2e\xa1"
         "\xb7\x7e\x51\x0d\x34\xb3\xed\xe7\x5e\xb8\x8a\xe9\xfe\x89\xf8\x0b\x85\x09"
         "\x76\x08\x78\x0d\x27\x59\x8e\x14\x43\x46\xa0\x91\xee\xaa\xff\x74\x8d\xbc"
         "\x98\xb9\x12\xad\x82\xdf\x2f\xf8\x9c\xe0",
         "\x1f\x03\x77\xd0\xed\x9b\xbc\xe9\x9b\xd3\x01\x06\xf8\x54\x90\x7d\x67\x6f"
         "\x19\xd7\x0b\xf3\x92\x8d\x60\xc0\x18\x5a\x24\xc1\xd7\x60\x82\x9c\x22\x37"
         "\x45\xe3\x9d\xa6\x76\x37\xe1\x7a\x13\xb4\x40\x63\xf4\xd8\xde\x41\x64\xfc"
         "\xe2\x42\x2e\x3f\xea\xe1\x28\x06\xa5\xac\x6a\xc1\x58\x0c\x84\xff\x9b\x6a"
         "\xe5\xbe\x4e\x8c\x4c\xe9\x97\xd5\x24\x30\x1b\x19\xdf\x87\x56\x85\x31\x56"
         "\x5a\xde\xe0\x6e\xc0\x1c\xcb\x51\x5b\x6e\xac\xf5\xb0\x60\x60\x2f\x62\x0a"
         "\xea\x62\x51\x2e\x5b\x1b\x99\x51\x3b\xac\xe9\xc5\x59\x7d\x0e\xb6\x51\x6c"
         "\x16\x7a\x7a\x13\xb4\x40\x69\x9b\x58\x16",
         1, 1088},
        {96, 128, 12,
         "\xae\x68\x52\xf8\x12\x10\x67\xcc\x4b\xf7\xa5\x76\x55\x77\xf3\x9e",
         "\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00",
         "\xa8\x63\x44\xf8\x36\x59\x2f\xf2\xda\xdd\x17\xce\xfe\x2a\xf2\xa2\x35\x87"
         "\x34\x0f\x35\xfc\xd8\xf2\x57\xa1\xcb\x19\x0c\x33\x14\xe1\x23\xeb\xc0\x88"
         "\x82\x05\x5f\x01\x5d\xfc\x53\x08\xdb\x34\x8e\x94\xe4\xa8\x26\x7f\xbc\xb7"
         "\x8b\xe1\x58\x2f\x2c\x91\xcd\x5b\x4a\xaa\x7a\xba\x5f\xd2\x9b\xf8\x7d\xea"
         "\x76\xb6\x64\xb3\x29\xd3\x02\x19\xa0\xdc\xe9\xb8\x90\x51\xa8\xde\x2e\xa1"
         "\xb7\x7e\x51\x0d\x34\xb3\xed\xe7\x5e\xb8\x8a\xe9\xfe\x89\xf8\x0b\x85\x09"
         "\x76\x08\x78\x0d\x27\x59\x8e\x14\x43\x46\xa0\x91\xee\xaa\xff\x74\x8d\xbc"
         "\x98\xb9\x77\xbd\x41\x4f\xab\xf8\x78\x1f\xed\x2b\x14\x89\xb5\x7b\x61\x5e"
         "\x88\x35\x46\x0f\x83\x5b\xc6\xe6\x61\x1d\xd8\x5e\xd3\xc3\xc6\xe8\xfb\x8e"
         "\x59\xdb\x31\x17\xf8\xcd\xc1\xd4\x2d\xef\xd8\x25\x9e\x88\x10\x58\xf2\xa6"
         "\x84\x4f\xa1\x32\x5f\x0e\xa2\x14\xf7\x03\x85\x06\x94\x4f\x83\x87\x04\x97"
         "\x5a\x8d\x9a\x73\x36\x2a\xe0\x6d\xa9\x1f\xbc\x2f\xd2\x9e\xd1\x7d\x2c\x89"
         "\x1f\xe1\xa0\x8f\x5d\x3e\xab\x9e\x79\x1a\x76\xc3\x0a\xc8\xcf\xcb\x35\x63"
         "\xd9\x46\x87\xaf\x74\x24\x47\xba\x60\xab\x33\x5d\xa8\xde\xfe\x1b\xc5\x3f"
         "\xac\xd9\xad\x94",
         "\x1f\x03\x77\xd0\xed\x9b\xbc\xe9\x9b\xd3\x01\x06\xf8\x54\x90\x7d\x67\x6f"
         "\x19\xd7\x0b\xf3\x92\x8d\x60\xc0\x18\x5a\x24\xc1\xd7\x60\x82\x9c\x22\x37"
         "\x45\xe3\x9d\xa6\x76\x37\xe1\x7a\x13\xb4\x40\x63\xf4\xd8\xde\x41\x64\xfc"
         "\xe2\x42\x2e\x3f\xea\xe1\x28\x06\xa5\xac\x6a\xc1\x58\x0c\x84\xff\x9b\x6a"
         "\xe5\xbe\x4e\x8c\x4c\xe9\x97\xd5\x24\x30\x1b\x19\xdf\x87\x56\x85\x31\x56"
         "\x5a\xde\xe0\x6e\xc0\x1c\xcb\x51\x5b\x6e\xac\xf5\xb0\x60\x60\x2f\x62\x0a"
         "\xea\x62\x51\x2e\x5b\x1b\x99\x51\x3b\xac\xe9\xc5\x59\x7d\x0e\xb6\x51\x6c"
         "\x16\x7a\x1f\x03\x77\xd0\xed\x9b\xbc\xe9\x9b\xd3\x01\x06\xf8\x54\x90\x7d"
         "\x67\x6f\x19\xd7\x0b\xf3\x92\x8d\x60\xc0\x18\x5a\x24\xc1\xd7\x60\x82\x9c"
         "\x22\x37\x45\xe3\x9d\xa6\x76\x37\xe1\x7a\x13\xb4\x40\x63\xf4\xd8\xde\x41"
         "\x64\xfc\xe2\x42\x2e\x3f\xea\xe1\x28\x06\xa5\xac\x6a\xc1\x58\x0c\x84\xff"
         "\x9b\x6a\xe5\xbe\x4e\x8c\x4c\xe9\x97\xd5\x24\x30\x1b\x19\xdf\x87\x56\x85"
         "\x31\x56\x5a\xde\xe0\x6e\xc0\x1c\xcb\x51\x5b\x6e\xac\xf5\xb0\x60\x60\x2f"
         "\x62\x0a\xea\x62\x51\x2e\x5b\x1b\x99\x51\x3b\xac\xe9\xc5\x59\x7d\x0e\xb6"
         "\x51\x6c\x16\x7a",
         1, 2048},
        {96, 128, 13,
         "\xae\x68\x52\xf8\x12\x10\x67\xcc\x4b\xf7\xa5\x76\x55\x77\xf3\x9e",
         "\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00",
         "\xa8\x63\x44\xf8\x36\x59\x2f\xf2\xda\xdd\x17\xce\xfe\x2a\xf2\xa2\x35\x87"
         "\x34\x0f\x35\xfc\xd8\xf2\x57\xa1\xcb\x19\x0c\x33\x14\xe1\x23\xeb\xc0\x88"
         "\x82\x05\x5f\x01\x5d\xfc\x53\x08\xdb\x34\x8e\x94\xe4\xa8\x26\x7f\xbc\xb7"
         "\x8b\xe1\x58\x2f\x2c\x91\xcd\x5b\x4a\xaa\x7a\xba\x5f\xd2\x9b\xf8\x7d\xea"
         "\x76\xb6\x64\xb3\x29\xd3\x02\x19\xa0\xdc\xe9\xb8\x90\x51\xa8\xde\x2e\xa1"
         "\xb7\x7e\x51\x0d\x34\xb3\xed\xe7\x5e\xb8\x8a\xe9\xfe\x89\xf8\x0b\x85\x09"
         "\x76\x08\x78\x0d\x27\x59\x8e\x14\x43\x46\xa0\x91\xee\xaa\xff\x74\x8d\xbc"
         "\x98\xb9\x77\xbd\x41\x4f\xab\xf8\x78\x1f\xed\x2b\x14\x89\xb5\x7b\x61\x5e"
         "\x88\x35\x46\x0f\x83\x5b\xc6\xe6\x61\x1d\xd8\x5e\xd3\xc3\xc6\xe8\xfb\x8e"
         "\x59\xdb\x31\x17\xf8\xcd\xc1\xd4\x2d\xef\xd8\x25\x9e\x88\x10\x58\xf2\xa6"
         "\x84\x4f\xa1\x32\x5f\x0e\xa2\x14\xf7\x03\x85\x06\x94\x4f\x83\x87\x04\x97"
         "\x5a\x8d\x9a\x73\x36\x2a\xe0\x6d\xa9\x1f\xbc\x2f\xd2\x9e\xd1\x7d\x2c\x89"
         "\x1f\xe1\xa0\x8f\x5d\x3e\xab\x9e\x79\x1a\x76\xc3\x0a\xc8\xcf\xcb\x35\x63"
         "\xd9\x46\x87\xaf\x74\x24\x47\xba\x60\xab\x33\x5d\xa8\xde\xfe\x1b\xc5\x3f"
         "\xac\xd9\xad\x94\x66\xb8\x3f\x3a\x21\x9f\xd0\x43\x46\xdd\x65\x8b\x44\x99"
         "\x66\x91\x64\xe2\x69\x6f\xbb\x85\x8c\xcc\x7f\xea\x96\xd1\x5e\xb4\x7c\xd0"
         "\xab\x02\x8d\xa3\x59\x3b\x8c\xd5\xd0\xe7\xb4\xc4",
         "\x1f\x03\x77\xd0\xed\x9b\xbc\xe9\x9b\xd3\x01\x06\xf8\x54\x90\x7d\x67\x6f"
         "\x19\xd7\x0b\xf3\x92\x8d\x60\xc0\x18\x5a\x24\xc1\xd7\x60\x82\x9c\x22\x37"
         "\x45\xe3\x9d\xa6\x76\x37\xe1\x7a\x13\xb4\x40\x63\xf4\xd8\xde\x41\x64\xfc"
         "\xe2\x42\x2e\x3f\xea\xe1\x28\x06\xa5\xac\x6a\xc1\x58\x0c\x84\xff\x9b\x6a"
         "\xe5\xbe\x4e\x8c\x4c\xe9\x97\xd5\x24\x30\x1b\x19\xdf\x87\x56\x85\x31\x56"
         "\x5a\xde\xe0\x6e\xc0\x1c\xcb\x51\x5b\x6e\xac\xf5\xb0\x60\x60\x2f\x62\x0a"
         "\xea\x62\x51\x2e\x5b\x1b\x99\x51\x3b\xac\xe9\xc5\x59\x7d\x0e\xb6\x51\x6c"
         "\x16\x7a\x1f\x03\x77\xd0\xed\x9b\xbc\xe9\x9b\xd3\x01\x06\xf8\x54\x90\x7d"
         "\x67\x6f\x19\xd7\x0b\xf3\x92\x8d\x60\xc0\x18\x5a\x24\xc1\xd7\x60\x82\x9c"
         "\x22\x37\x45\xe3\x9d\xa6\x76\x37\xe1\x7a\x13\xb4\x40\x63\xf4\xd8\xde\x41"
         "\x64\xfc\xe2\x42\x2e\x3f\xea\xe1\x28\x06\xa5\xac\x6a\xc1\x58\x0c\x84\xff"
         "\x9b\x6a\xe5\xbe\x4e\x8c\x4c\xe9\x97\xd5\x24\x30\x1b\x19\xdf\x87\x56\x85"
         "\x31\x56\x5a\xde\xe0\x6e\xc0\x1c\xcb\x51\x5b\x6e\xac\xf5\xb0\x60\x60\x2f"
         "\x62\x0a\xea\x62\x51\x2e\x5b\x1b\x99\x51\x3b\xac\xe9\xc5\x59\x7d\x0e\xb6"
         "\x51\x6c\x16\x7a\xed\x52\x55\xb9\x76\x6c\x5e\x6e\x76\x97\x00\xc7\xeb\xfe"
         "\xec\x10\x94\x2c\xa9\xaf\x9b\x09\x19\xb3\x17\x29\x96\xba\x8e\xac\x3d\x0a"
         "\x9b\x70\x54\x0f\x1e\xd4\xe8\x13\xe6\x8f\xad\xfd",
         1, 2400},
        {96, 128, 14,
         "\xae\x68\x52\xf8\x12\x10\x67\xcc\x4b\xf7\xa5\x76\x55\x77\xf3\x9e",
         "\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00",
         "\xa8\x63\x44\xf8\x36\x59\x2f\xf2\xda\xdd\x17\xce\xfe\x2a\xf2\xa2\x35\x87"
         "\x34\x0f\x35\xfc\xd8\xf2\x57\xa1\xcb\x19\x0c\x33\x14\xe1\x23\xeb\xc0\x88"
         "\x82\x05\x5f\x01\x5d\xfc\x53\x08\xdb\x34\x8e\x94\xe4\xa8\x26\x7f\xbc\xb7"
         "\x8b\xe1\x58\x2f\x2c\x91\xcd\x5b\x4a\xaa\x7a\xba\x5f\xd2\x9b\xf8\x7d\xea"
         "\x76\xb6\x64\xb3\x29\xd3\x02\x19\xa0\xdc\xe9\xb8\x90\x51\xa8\xde\x2e\xa1"
         "\xb7\x7e\x51\x0d\x34\xb3\xed\xe7\x5e\xb8\x8a\xe9\xfe\x89\xf8\x0b\x85\x09"
         "\x76\x08\x78\x0d\x27\x59\x8e\x14\x43\x46\xa0\x91\xee\xaa\xff\x74\x8d\xbc"
         "\x98\xb9\x77\xbd\x41\x4f\xab\xf8\x78\x1f\xed\x2b\x14\x89\xb5\x7b\x61\x5e"
         "\x88\x35\x46\x0f\x83\x5b\xc6\xe6\x61\x1d\xd8\x5e\xd3\xc3\xc6\xe8\xfb\x8e"
         "\x59\xdb\x31\x17\xf8\xcd\xc1\xd4\x2d\xef\xd8\x25\x9e\x88\x10\x58\xf2\xa6"
         "\x84\x4f\xa1\x32\x5f\x0e\xa2\x14\xf7\x03\x85\x06\x94\x4f\x83\x87\x04\x97"
         "\x5a\x8d\x9a\x73\x36\x2a\xe0\x6d\xa9\x1f\xbc\x2f\xd2\x9e\xd1\x7d\x2c\x89"
         "\x1f\xe1\xa0\x8f\x5d\x3e\xab\x9e\x79\x1a\x76\xc3\x0a\xc8\xcf\xcb\x35\x63"
         "\xd9\x46\x87\xaf\x74\x24\x47\xba\x60\xab\x33\x5d\xa8\xde\xfe\x1b\xc5\x3f"
         "\xac\xd9\xad\x94\x66\xb8\x3f\x3a\x21\x9f\xd0\x43\x46\xdd\x65\x8b\x44\x99"
         "\x66\x91\x64\xe2\x69\x6f\xbb\x85\x8c\xcc\x7f\xea\x96\xd1\x5e\xb4\x7c\xd0"
         "\xab\x02\x8d\xa3\x59\x3b\x8c\xd5\xd0\xe7\xb4\xc4\x90\x41\x9f\x78\x4e\x82"
         "\x9e\xe4\x1b\x97\xa9\xa4\x7b\x48\xad\x56\xc0\xe4\x86\x52\xfc\xad\x93\x0b"
         "\x7d\x38\xce\x73\x64\xbd\xf7\x00\x7b\xe6\x46\x03\x2f\x4b\x75\x9f\x3a\x2d"
         "\x32\x42\xfe\x80\x74\x89\x27\x34\xce\x5e\xbf\xbe\x07\x50\x91\x08\x27\x2b"
         "\x32\x77\xa7\xff\x83\xb1\xab\xc8\x98\xbe\xac\x33\x7c\x47\x19\x33\x6f\x4d"
         "\xbe\x3e\xdc\xe0\x87\xfb",
         "\x1f\x03\x77\xd0\xed\x9b\xbc\xe9\x9b\xd3\x01\x06\xf8\x54\x90\x7d\x67\x6f"
         "\x19\xd7\x0b\xf3\x92\x8d\x60\xc0\x18\x5a\x24\xc1\xd7\x60\x82\x9c\x22\x37"
         "\x45\xe3\x9d\xa6\x76\x37\xe1\x7a\x13\xb4\x40\x63\xf4\xd8\xde\x41\x64\xfc"
         "\xe2\x42\x2e\x3f\xea\xe1\x28\x06\xa5\xac\x6a\xc1\x58\x0c\x84\xff\x9b\x6a"
         "\xe5\xbe\x4e\x8c\x4c\xe9\x97\xd5\x24\x30\x1b\x19\xdf\x87\x56\x85\x31\x56"
         "\x5a\xde\xe0\x6e\xc0\x1c\xcb\x51\x5b\x6e\xac\xf5\xb0\x60\x60\x2f\x62\x0a"
         "\xea\x62\x51\x2e\x5b\x1b\x99\x51\x3b\xac\xe9\xc5\x59\x7d\x0e\xb6\x51\x6c"
         "\x16\x7a\x1f\x03\x77\xd0\xed\x9b\xbc\xe9\x9b\xd3\x01\x06\xf8\x54\x90\x7d"
         "\x67\x6f\x19\xd7\x0b\xf3\x92\x8d\x60\xc0\x18\x5a\x24\xc1\xd7\x60\x82\x9c"
         "\x22\x37\x45\xe3\x9d\xa6\x76\x37\xe1\x7a\x13\xb4\x40\x63\xf4\xd8\xde\x41"
         "\x64\xfc\xe2\x42\x2e\x3f\xea\xe1\x28\x06\xa5\xac\x6a\xc1\x58\x0c\x84\xff"
         "\x9b\x6a\xe5\xbe\x4e\x8c\x4c\xe9\x97\xd5\x24\x30\x1b\x19\xdf\x87\x56\x85"
         "\x31\x56\x5a\xde\xe0\x6e\xc0\x1c\xcb\x51\x5b\x6e\xac\xf5\xb0\x60\x60\x2f"
         "\x62\x0a\xea\x62\x51\x2e\x5b\x1b\x99\x51\x3b\xac\xe9\xc5\x59\x7d\x0e\xb6"
         "\x51\x6c\x16\x7a\xed\x52\x55\xb9\x76\x6c\x5e\x6e\x76\x97\x00\xc7\xeb\xfe"
         "\xec\x10\x94\x2c\xa9\xaf\x9b\x09\x19\xb3\x17\x29\x96\xba\x8e\xac\x3d\x0a"
         "\x9b\x70\x54\x0f\x1e\xd4\xe8\x13\xe6\x8f\xad\xfd\xfd\x13\xcf\xd5\x94\x06"
         "\xa0\x24\x79\xc0\xf8\x05\x3d\x19\xeb\x96\xda\x31\xae\xf5\x4d\x82\x2c\x23"
         "\x03\x9a\x43\x85\x94\x36\x30\xe8\x0a\x9b\x1f\x05\x6e\x4b\xa5\x98\x78\xbe"
         "\x73\x0d\x8c\x60\x55\x88\xd6\xa3\x80\x13\x19\xdb\xf8\xcd\xa7\xdc\x28\x4c"
         "\x09\xaf\xfe\x88\x77\xe1\x6e\x12\x57\x5a\xa8\xc6\x38\xcf\xf5\x0d\x42\x2c"
         "\x67\xb3\x22\x6f\x3d\x7d",
         1, 3072},
        {128, 128, 15,
         "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
         "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
         "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d"
         "\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46"
         "\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f"
         "\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
         "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce\x98\x06"
         "\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd\xff\x5a\xe4\xdf\x3e"
         "\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab\x1e\x03\x1d\xda\x2f\xbe"
         "\x03\xd1\x79\x21\x70\xa0\xf3\x00\x9c\xee",
         1, 512},
        {0, 0, 0, NULL, NULL, NULL, NULL, 0, 0}
};

        const struct cipher_test ctr_bit_test_json[] = {
        /* Vectors from https://tools.ietf.org/html/rfc3686 */
        {128, 128, 1,
         "\xd3\xc5\xd5\x92\x32\x7f\xb1\x1c\x40\x35\xc6\x68\x0a\xf8\xc6\xd1",
         "\x39\x8a\x59\xb4\xac\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
         "\x98\x1b\xa6\x82\x4c\x1b\xfb\x1a\xb4\x85\x47\x20\x29\xb7\x1d\x80\x8c\xe3"
         "\x3e\x2c\xc3\xc0\xb5\xfc\x1f\x3d\xe8\xa6\xdc\x66\xb1\xf7",
         "\xe9\xfe\xd8\xa6\x3d\x15\x53\x04\xd7\x1d\xf2\x0b\xf3\xe8\x22\x14\xb2\x0e"
         "\xd7\xda\xd2\xf2\x33\xdc\x3c\x22\xd7\xbd\xee\xed\x8e\x7f",
         1, 253},
        {128, 128, 2,
         "\x2b\xd6\x45\x9f\x82\xc4\x40\xe0\x95\x2c\x49\x10\x48\x05\xff\x48",
         "\xc6\x75\xa6\x4b\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
         "\x7e\xc6\x12\x72\x74\x3b\xf1\x61\x47\x26\x44\x6a\x6c\x38\xce\xd1\x66\xf6"
         "\xca\x76\xeb\x54\x30\x04\x42\x86\x34\x6c\xef\x13\x0f\x92\x92\x2b\x03\x45"
         "\x0d\x3a\x99\x75\xe5\xbd\x2e\xa0\xeb\x55\xad\x8e\x1b\x19\x9e\x3e\xc4\x31"
         "\x60\x20\xe9\xa1\xb2\x85\xe7\x62\x79\x53\x59\xb7\xbd\xfd\x39\xbe\xf4\xb2"
         "\x48\x45\x83\xd5\xaf\xe0\x82\xae\xe6\x38\xbf\x5f\xd5\xa6\x06\x19\x39\x01"
         "\xa0\x8f\x4a\xb4\x1a\xab\x9b\x13\x48\x83",
         "\x59\x61\x60\x53\x53\xc6\x4b\xdc\xa1\x5b\x19\x5e\x28\x85\x53\xa9\x10\x63"
         "\x25\x06\xd6\x20\x0a\xa7\x90\xc4\xc8\x06\xc9\x99\x04\xcf\x24\x45\xcc\x50"
         "\xbb\x1c\xf1\x68\xa4\x96\x73\x73\x4e\x08\x1b\x57\xe3\x24\xce\x52\x59\xc0"
         "\xe7\x8d\x4c\xd9\x7b\x87\x09\x76\x50\x3c\x09\x43\xf2\xcb\x5a\xe8\xf0\x52"
         "\xc7\xb7\xd3\x92\x23\x95\x87\xb8\x95\x60\x86\xbc\xab\x18\x83\x60\x42\xe2"
         "\xe6\xce\x42\x43\x2a\x17\x10\x5c\x53\xd3",
         1, 798},
        {128, 128, 3,
         "\x0a\x8b\x6b\xd8\xd9\xb0\x8b\x08\xd6\x4e\x32\xd1\x81\x77\x77\xfb",
         "\x54\x4d\x49\xcd\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
         "\xfd\x40\xa4\x1d\x37\x0a\x1f\x65\x74\x50\x95\x68\x7d\x47\xba\x1d\x36\xd2"
         "\x34\x9e\x23\xf6\x44\x39\x2c\x8e\xa9\xc4\x9d\x40\xc1\x32\x71\xaf\xf2\x64"
         "\xd0\xf2\x4b",
         "\x75\x75\x0d\x37\xb4\xbb\xa2\xa4\xde\xdb\x34\x23\x5b\xd6\x8c\x66\x45\xac"
         "\xda\xac\xa4\x81\x38\xa3\xb0\xc4\x71\xe2\xa7\x04\x1a\x57\x64\x23\xd2\x92"
         "\x72\x87\xf3",
         1, 310},
        {128, 128, 4,
         "\xaa\x1f\x95\xae\xa5\x33\xbc\xb3\x2e\xb6\x3b\xf5\x2d\x8f\x83\x1a",
         "\x72\xd8\xc6\x71\x84\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
         "\xfb\x1b\x96\xc5\xc8\xba\xdf\xb2\xe8\xe8\xed\xfd\xe7\x8e\x57\xf2\xad\x81"
         "\xe7\x41\x03\xfc\x43\x0a\x53\x4d\xcc\x37\xaf\xce\xc7\x0e\x15\x17\xbb\x06"
         "\xf2\x72\x19\xda\xe4\x90\x22\xdd\xc4\x7a\x06\x8d\xe4\xc9\x49\x6a\x95\x1a"
         "\x6b\x09\xed\xbd\xc8\x64\xc7\xad\xbd\x74\x0a\xc5\x0c\x02\x2f\x30\x82\xba"
         "\xfd\x22\xd7\x81\x97\xc5\xd5\x08\xb9\x77\xbc\xa1\x3f\x32\xe6\x52\xe7\x4b"
         "\xa7\x28\x57\x60\x77\xce\x62\x8c\x53\x5e\x87\xdc\x60\x77\xba\x07\xd2\x90"
         "\x68\x59\x0c\x8c\xb5\xf1\x08\x8e\x08\x2c\xfa\x0e\xc9\x61\x30\x2d\x69\xcf"
         "\x3d\x47",
         "\xdf\xb4\x40\xac\xb3\x77\x35\x49\xef\xc0\x46\x28\xae\xb8\xd8\x15\x62\x75"
         "\x23\x0b\xdc\x69\x0d\x94\xb0\x0d\x8d\x95\xf2\x8c\x4b\x56\x30\x7f\x60\xf4"
         "\xca\x55\xeb\xa6\x61\xeb\xba\x72\xac\x80\x8f\xa8\xc4\x9e\x26\x78\x8e\xd0"
         "\x4a\x5d\x60\x6c\xb4\x18\xde\x74\x87\x8b\x9a\x22\xf8\xef\x29\x59\x0b\xc4"
         "\xeb\x57\xc9\xfa\xf7\xc4\x15\x24\xa8\x85\xb8\x97\x9c\x42\x3f\x2f\x8f\x8e"
         "\x05\x92\xa9\x87\x92\x01\xbe\x7f\xf9\x77\x7a\x16\x2a\xb8\x10\xfe\xb3\x24"
         "\xba\x74\xc4\xc1\x56\xe0\x4d\x39\x09\x72\x09\x65\x3a\xc3\x3e\x5a\x5f\x2d"
         "\x88\x67",
         1, 1022},
        {128, 128, 5,
         "\x96\x18\xae\x46\x89\x1f\x86\x57\x8e\xeb\xe9\x0e\xf7\xa1\x20\x2e",
         "\xc6\x75\xa6\x4b\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
         "\x8d\xaa\x17\xb1\xae\x05\x05\x29\xc6\x82\x7f\x28\xc0\xef\x6a\x12\x42\xe9"
         "\x3f\x8b\x31\x4f\xb1\x8a\x77\xf7\x90\xae\x04\x9f\xed\xd6\x12\x26\x7f\xec"
         "\xae\xfc\x45\x01\x74\xd7\x6d\x9f\x9a\xa7\x75\x5a\x30\xcd\x90\xa9\xa5\x87"
         "\x4b\xf4\x8e\xaf\x70\xee\xa3\xa6\x2a\x25\x0a\x8b\x6b\xd8\xd9\xb0\x8b\x08"
         "\xd6\x4e\x32\xd1\x81\x77\x77\xfb\x54\x4d\x49\xcd\x49\x72\x0e\x21\x9d\xbf"
         "\x8b\xbe\xd3\x39\x04\xe1\xfd\x40\xa4\x1d\x37\x0a\x1f\x65\x74\x50\x95\x68"
         "\x7d\x47\xba\x1d\x36\xd2\x34\x9e\x23\xf6\x44\x39\x2c\x8e\xa9\xc4\x9d\x40"
         "\xc1\x32\x71\xaf\xf2\x64\xd0\xf2\x48\x41\xd6\x46\x5f\x09\x96\xff\x84\xe6"
         "\x5f\xc5\x17\xc5\x3e\xfc\x33\x63\xc3\x84\x92\xaf",
         "\x91\x9c\x8c\x33\xd6\x67\x89\x70\x3d\x05\xa0\xd7\xce\x82\xa2\xae\xac\x4e"
         "\xe7\x6c\x0f\x4d\xa0\x50\x33\x5e\x8a\x84\xe7\x89\x7b\xa5\xdf\x2f\x36\xbd"
         "\x51\x3e\x3d\x0c\x85\x78\xc7\xa0\xfc\xf0\x43\xe0\x3a\xa3\xa3\x9f\xba\xad"
         "\x7d\x15\xbe\x07\x4f\xaa\x5d\x90\x29\xf7\x1f\xb4\x57\xb6\x47\x83\x47\x14"
         "\xb0\xe1\x8f\x11\x7f\xca\x10\x67\x79\x45\x09\x6c\x8c\x5f\x32\x6b\xa8\xd6"
         "\x09\x5e\xb2\x9c\x3e\x36\xcf\x24\x5d\x16\x22\xaa\xfe\x92\x1f\x75\x66\xc4"
         "\xf5\xd6\x44\xf2\xf1\xfc\x0e\xc6\x84\xdd\xb2\x13\x49\x74\x76\x22\xe2\x09"
         "\x29\x5d\x27\xff\x3f\x95\x62\x33\x71\xd4\x9b\x14\x7c\x0a\xf4\x86\x17\x1f"
         "\x22\xcd\x04\xb1\xcb\xeb\x26\x58\x22\x3e\x69\x3f",
         1, 1245},
        {128, 128, 6,
         "\x54\xf4\xe2\xe0\x4c\x83\x78\x6e\xec\x8f\xb5\xab\xe8\xe3\x65\x66",
         "\xac\xa4\xf5\x0f\x58\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
         "\x40\x98\x1b\xa6\x82\x4c\x1b\xfb\x42\x86\xb2\x99\x78\x3d\xaf\x44\x2c\x09"
         "\x9f\x7a\xb0\xf5\x8d\x5c\x8e\x46\xb1\x04\xf0\x8f\x01\xb4\x1a\xb4\x85\x47"
         "\x20\x29\xb7\x1d\x36\xbd\x1a\x3d\x90\xdc\x3a\x41\xb4\x6d\x51\x67\x2a\xc4"
         "\xc9\x66\x3a\x2b\xe0\x63\xda\x4b\xc8\xd2\x80\x8c\xe3\x3e\x2c\xcc\xbf\xc6"
         "\x34\xe1\xb2\x59\x06\x08\x76\xa0\xfb\xb5\xa4\x37\xeb\xcc\x8d\x31\xc1\x9e"
         "\x44\x54\x31\x87\x45\xe3\xfa\x16\xbb\x11\xad\xae\x24\x88\x79\xfe\x52\xdb"
         "\x25\x43\xe5\x3c\xf4\x45\xd3\xd8\x28\xce\x0b\xf5\xc5\x60\x59\x3d\x97\x27"
         "\x8a\x59\x76\x2d\xd0\xc2\xc9\xcd\x68\xd4\x49\x6a\x79\x25\x08\x61\x40\x14"
         "\xb1\x3b\x6a\xa5\x11\x28\xc1\x8c\xd6\xa9\x0b\x87\x97\x8c\x2f\xf1\xca\xbe"
         "\x7d\x9f\x89\x8a\x41\x1b\xfd\xb8\x4f\x68\xf6\x72\x7b\x14\x99\xcd\xd3\x0d"
         "\xf0\x44\x3a\xb4\xa6\x66\x53\x33\x0b\xcb\xa1\x10\x5e\x4c\xec\x03\x4c\x73"
         "\xe6\x05\xb4\x31\x0e\xaa\xad\xcf\xd5\xb0\xca\x27\xff\xd8\x9d\x14\x4d\xf4"
         "\x79\x27\x59\x42\x7c\x9c\xc1\xf8\xcd\x8c\x87\x20\x23\x64\xb8\xa6\x87\x95"
         "\x4c\xb0\x5a\x8d\x4e\x2d\x99\xe7\x3d\xb1\x60\xde\xb1\x80\xad\x08\x41\xe9"
         "\x67\x41\xa5\xd5\x9f\xe4\x18\x9f\x15\x42\x00\x26\xfe\x4c\xd1\x21\x04\x93"
         "\x2f\xb3\x8f\x73\x53\x40\x43\x8a\xaf\x7e\xca\x6f\xd5\xcf\xd3\xa1\x95\xce"
         "\x5a\xbe\x65\x27\x2a\xf6\x07\xad\xa1\xbe\x65\xa6\xb4\xc9\xc0\x69\x32\x34"
         "\x09\x2c\x4d\x01\x8f\x17\x56\xc6\xdb\x9d\xc8\xa6\xd8\x0b\x88\x81\x38\x61"
         "\x6b\x68\x12\x62\xf9\x54\xd0\xe7\x71\x17\x48\x78\x0d\x92\x29\x1d\x86\x29"
         "\x99\x72\xdb\x74\x1c\xfa\x4f\x37\xb8\xb5\x6c\xdb\x18\xa7\xca\x82\x18\xe8"
         "\x6e\x4b\x4b\x71\x6a\x4d\x04\x37\x1f\xbe\xc2\x62\xfc\x5a\xd0\xb3\x81\x9b"
         "\x18\x7b\x97\xe5\x5b\x1a\x4d\x7c\x19\xee\x24\xc8\xb4\xd7\x72\x3c\xfe\xdf"
         "\x04\x5b\x8a\xca\xe4\x86\x95\x17\xd8\x0e\x50\x61\x5d\x90\x35\xd5\xd9\xc5"
         "\xa4\x0a\xf6\x02\x28\x0b\x54\x25\x97\xb0\xcb\x18\x61\x9e\xeb\x35\x92\x57"
         "\x59\xd1\x95\xe1\x00\xe8\xe4\xaa\x0c\x38\xa3\xc2\xab\xe0\xf3\xd8\xff\x04"
         "\xf3\xc3\x3c\x29\x50\x69\xc2\x36\x94\xb5\xbb\xea\xcd\xd5\x42\xe2\x8e\x8a"
         "\x94\xed\xb9\x11\x9f\x41\x2d\x05\x4b\xe1\xfa\x72\x00\xb0\x97",
         "\x5c\xb7\x2c\x6e\xdc\x87\x8f\x15\x66\xe1\x02\x53\xaf\xc3\x64\xc9\xfa\x54"
         "\x0d\x91\x4d\xb9\x4c\xbe\xe2\x75\xd0\x91\x7c\xa6\xaf\x0d\x77\xac\xb4\xef"
         "\x3b\xbe\x1a\x72\x2b\x2e\xf5\xbd\x1d\x4b\x8e\x2a\xa5\x02\x4e\xc1\x38\x8a"
         "\x20\x1e\x7b\xce\x79\x20\xae\xc6\x15\x89\x5f\x76\x3a\x55\x64\xdc\xc4\xc4"
         "\x82\xa2\xee\x1d\x8b\xfe\xcc\x44\x98\xec\xa8\x3f\xbb\x75\xf9\xab\x53\x0e"
         "\x0d\xaf\xbe\xde\x2f\xa5\x89\x5b\x82\x99\x1b\x62\x77\xc5\x29\xe0\xf2\x52"
         "\x9d\x7f\x79\x60\x6b\xe9\x67\x06\x29\x6d\xed\xfa\x9d\x74\x12\xb6\x16\x95"
         "\x8c\xb5\x63\xc6\x78\xc0\x28\x25\xc3\x0d\x0a\xee\x77\xc4\xc1\x46\xd2\x76"
         "\x54\x12\x42\x1a\x80\x8d\x13\xce\xc8\x19\x69\x4c\x75\xad\x57\x2e\x9b\x97"
         "\x3d\x94\x8b\x81\xa9\x33\x7c\x3b\x2a\x17\x19\x2e\x22\xc2\x06\x9f\x7e\xd1"
         "\x16\x2a\xf4\x4c\xde\xa8\x17\x60\x36\x65\xe8\x07\xce\x40\xc8\xe0\xdd\x9d"
         "\x63\x94\xdc\x6e\x31\x15\x3f\xe1\x95\x5c\x47\xaf\xb5\x1f\x26\x17\xee\x0c"
         "\x5e\x3b\x8e\xf1\xad\x75\x74\xed\x34\x3e\xdc\x27\x43\xcc\x94\xc9\x90\xe1"
         "\xf1\xfd\x26\x42\x53\xc1\x78\xde\xa7\x39\xc0\xbe\xfe\xeb\xcd\x9f\x9b\x76"
         "\xd4\x9c\x10\x15\xc9\xfe\xcf\x50\xe5\x3b\x8b\x52\x04\xdb\xcd\x3e\xed\x86"
         "\x38\x55\xda\xbc\xdc\xc9\x4b\x31\xe3\x18\x02\x15\x68\x85\x5c\x8b\x9e\x52"
         "\xa9\x81\x95\x7a\x11\x28\x27\xf9\x78\xba\x96\x0f\x14\x47\x91\x1b\x31\x7b"
         "\x55\x11\xfb\xcc\x7f\xb1\x3a\xc1\x53\xdb\x74\x25\x11\x17\xe4\x86\x1e\xb9"
         "\xe8\x3b\xff\xff\xc4\xeb\x77\x55\x57\x90\x38\xe5\x79\x24\xb1\xf7\x8b\x3e"
         "\x1a\xd9\x0b\xab\x2a\x07\x87\x1b\x72\xdb\x5e\xef\x96\xc3\x34\x04\x49\x66"
         "\xdb\x0c\x37\xca\xfd\x1a\x89\xe5\x64\x6a\x35\x80\xeb\x64\x65\xf1\x21\xdc"
         "\xe9\xcb\x88\xd8\x5b\x96\xcf\x23\xcc\xcc\xd4\x28\x07\x67\xbe\xe8\xee\xb2"
         "\x3d\x86\x52\x46\x1d\xb6\x49\x31\x03\x00\x3b\xaf\x89\xf5\xe1\x82\x61\xea"
         "\x43\xc8\x4a\x92\xeb\xff\xff\xe4\x90\x9d\xc4\x6c\x51\x92\xf8\x25\xf7\x70"
         "\x60\x0b\x96\x02\xc5\x57\xb5\xf8\xb4\x31\xa7\x9d\x45\x97\x7d\xd9\xc4\x1b"
         "\x86\x3d\xa9\xe1\x42\xe9\x00\x20\xcf\xd0\x74\xd6\x92\x7b\x7a\xb3\xb6\x72"
         "\x5d\x1a\x6f\x3f\x98\xb9\xc9\xda\xa8\x98\x2a\xff\x06\x78\x2f",
         1, 3861},
        {128, 192, 7,
         "\x02\xbf\x39\x1e\xe8\xec\xb1\x59\xb9\x59\x61\x7b\x09\x65\x27\x9b\xf5\x9b"
         "\x60\xa7\x86\xd3\xe0\xfe",
         "\x00\x07\xbd\xfd\x5c\xbd\x60\x27\x8d\xcc\x09\x12\x00\x00\x00\x01",
         "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"
         "\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x2f",
         "\x96\x89\x3f\xc5\x5e\x5c\x72\x2f\x54\x0b\x7d\xd1\xdd\xf7\xe7\x58\xd2\x88"
         "\xbc\x95\xc6\x91\x65\x88\x45\x36\xc8\x11\x66\x2f\x21\x88\xab\xee\x09\x3f",
         1, 284},
        {128, 256, 8,
         "\x77\x6b\xef\xf2\x85\x1d\xb0\x6f\x4c\x8a\x05\x42\xc8\x69\x6f\x6c\x6a\x81"
         "\xaf\x1e\xec\x96\xb4\xd3\x7f\xc1\xd6\x89\xe6\xc1\xc1\x04",
         "\x00\x00\x00\x60\xdb\x56\x72\xc9\x7a\xa8\xf0\xb2\x00\x00\x00\x01",
         "\x53\x69\x6e\x67\x6c\x65\x20\x62\x6c\x6f\x63\x6b\x20\x6d\x73\x6f",
         "\x14\x5a\xd0\x1d\xbf\x82\x4e\xc7\x56\x08\x63\xdc\x71\xe3\xe0\xcf", 1,
         124},
        {0, 0, 0, NULL, NULL, NULL, NULL, 0, 0}
};

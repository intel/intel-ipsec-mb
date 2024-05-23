# Multi-Process Test

This test is designed to exercise fail-over scenario. In this scenario one process, called primary, is actively processing crypto requests.
Another process, called secondary, is passive but it can take over crypto operations at any point of time if the primary process fails.

## Contents
1. Overview
2. Running
3. Multi-Buffer Manager (MB MGR) Notes
4. OS Implementation Notes

## 1. Overview

The test uses two applications, one is used to represent the primary process and another one the secondary one.
Operation flow of two processes looks as described in the table below.

| PRIMARY PROCESS | SECONDARY PROCESS |
| :-------- | -----------: |
| [START]   |  |
| INITIALIZE INFO SHARED MEMORY |  |
| INITIALIZE DATA SHARED MEMORY |  |
| INITIALIZE MB MGR |  |
| INITIALIZE MEMORY FOR 15 CRYPTO OPERATIONS |  |
| PRODUCE EXPECTED CRYPTO RESULTS (out-of-place) |  |
| SEND 15 CRYPTO REQUESTS (in-place) AND COLLECT RESPONSES IF ANY |  |
| UPDATE INFO SHARED MEMORY WITH CRYPTO REQUEST/RESPONSE DETAILS |  |
| START SECONDARY PROCESS --> | --> [START] |
|  | OPEN INFO SHARED MEMORY |
|  | OPEN DATA SHARED MEMORY |
|  | INITIALIZE MB MGR IN SHARED MEMORY |
|  | COMPLETE OUTSTANDING CRYPTO OPERATIONS |
|  | CHECK NUMBER OF PROCESSED BUFFERS IS EQUAL NUMBER OF REQUESTS |
| CHECK CRYPTO RESPONSE BUFFERS MATCH EXPECTED OUTPUT <-- | <-- [END] |
| FREE ALLOCATED RESOURCES | |
| [END] | |

## 2. Running

Primary process requires path name of the secondary process application as an argument.
Example: `> ./imb-mp-primary ${PWD}/imb-mp-secondary`

## 3. Multi-Buffer Manager (MB MGR) Notes

See `mp_imb.c` file and `init_imb()` function as reference for setting up multi-buffer manager in the primary process and fail-over initialization in the secondary process.
Note that for fail-over scenario, all crypto operations need to be done on data structures allocated in shared memory. Virtual addresses of the buffers and associated data structures need to be identical in the primary and secondary processes.

## 4. OS Implementation notes

### Linux

No issues encountered. Virtual address given automatically to the primary process shared memory at `mmap()` is good to map in the secondary process.

### FreeBSD

Using arbitrary virtual address to allocate common virtual addresses for the primary and secondary processes. Address growth from the bottom to top.
`MAP_PREFAULT_READ` was found to be required on FreeBSD system when calling `mmap()`. Otherwise the secondary process was crashing when accessing open shared memory.

### Windows

Shared memory handle cannot be closed by the primary process before executing `system()` otherwise secondary process cannot map named shared memory.
Using maximum application address from `GetSystemInfo()` to allocate common virtual addresses for the primary and secondary processes. Stack based approach applied here and moving from the top address down.

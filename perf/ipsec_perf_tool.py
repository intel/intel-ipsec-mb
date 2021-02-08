#!/usr/bin/env python3

"""
**********************************************************************
  Copyright(c) 2020, Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************
"""

import threading
import queue
import os
import sys
import subprocess
import platform
import time
import argparse
import textwrap

# number of variants to run
TOTAL_VARIANTS = 0
# dictionary to store env vars
ENVS = None
# queues to store todo and completed variants
TODO_Q = None
DONE_Q = None
# don't output info to stderr if set
QUIET = False
# perf application name
PERF_APP = ''
# exit on error flag
EXIT_ERROR = False


class Variant:
    """Class to setup and run test case variant"""
    def __init__(self, idx=None, arch=None, direction='encrypt', cipher_alg=None, \
                 hash_alg=None, aead_alg=None, sizes=None, offset=None):
        """Build perf app command line"""
        global PERF_APP

        self.idx = idx
        self.arch = arch
        self.direction = direction
        self.cipher_alg = cipher_alg
        self.hash_alg = hash_alg
        self.aead_alg = aead_alg
        self.sizes = sizes
        self.offset = offset
        self.cmd = '{} --no-progress-bar '.format(PERF_APP)
        self.cmd_output = ''
        self.out = []
        self.core = None

        if self.arch is not None:
            self.cmd += ' --arch {}'.format(self.arch)

        if self.offset is not None:
            self.cmd += ' -o {}'.format(str(self.offset))

        if self.aead_alg is not None:
            if self.cipher_alg is not None or \
               self.hash_alg is not None:
                print("Invalid combination: aead + cipher / hash", \
                      file=sys.stderr)
                sys.exit(1)
            self.cmd += ' --aead-algo {}'.format(self.aead_alg)

        if self.cipher_alg is not None:
            if self.aead_alg is not None:
                print("Invalid combination: aead + cipher", file=sys.stderr)
                sys.exit(1)
            self.cmd += ' --cipher-algo {}'.format(self.cipher_alg)

        if self.hash_alg is not None:
            if self.aead_alg is not None:
                print("Invalid combination: aead + hash", file=sys.stderr)
                sys.exit(1)
            self.cmd += ' --hash-algo {}'.format(self.hash_alg)

        if self.cipher_alg is not None or \
           self.aead_alg is not None:
            self.cmd += ' --cipher-dir {}'.format(self.direction)

        if self.sizes is not None:
            self.cmd += ' --job-size {}'.format(self.sizes)

    def run(self):
        """Run perf app and store output"""
        try:
            self.cmd_output = \
                subprocess.run(self.cmd.split(), \
                               stdout=subprocess.PIPE, \
                               stderr=subprocess.PIPE, \
                               env=ENVS, check=True).stdout.decode('utf-8')
            return True
        except:
            return False

    def set_core(self, core):
        """Set core to run perf app on"""
        self.core = core
        mask = 1 << core
        self.cmd += ' --cores {}'.format(str(hex(mask)))

    def get_output(self):
        """Get output from run"""
        return self.cmd_output

    def get_cmd(self):
        """Get variant command line"""
        return self.cmd

    def get_idx(self):
        """Get assigned index"""
        return self.idx

    def get_info(self):
        """Get variant details"""

        if self.idx is None:
            idx = ''
        else:
            idx = self.idx

        if self.cipher_alg is None:
            cipher_alg = ''
        else:
            cipher_alg = self.cipher_alg

        if self.hash_alg is None:
            hash_alg = ''
        else:
            hash_alg = self.hash_alg

        if self.aead_alg is None:
            aead_alg = ''
        else:
            aead_alg = self.aead_alg

        if self.core is None:
            core = ''
        else:
            core = self.core

        if self.direction is None:
            direction = 'n/a'
        else:
            direction = self.direction

        alg = '{}{}{}'.format(cipher_alg, hash_alg, aead_alg)

        info = '{0:<5} {1:<4} {2:<6} {3:<7} {4:<40}'\
            .format(idx, core, self.arch, direction, alg)

        return info


def init_vars():
    """Initialize global variables"""
    global TOTAL_VARIANTS
    global ENVS
    global TODO_Q
    global DONE_Q
    global QUIET
    global PERF_APP

    # init vars
    TOTAL_VARIANTS = 0
    QUIET = False

    # include perf directory in PATH
    path = '{}:{}'.format(os.getenv('PATH'), os.getenv('PWD'))

    # set LD_LIBRARY_PATH if not already set
    lib_path = os.getenv('LD_LIBRARY_PATH')
    if lib_path is None:
        lib_path = '../lib'

    # create env vars dictionary to pass to subprocess module
    ENVS = {'PATH' : path, 'LD_LIBRARY_PATH' : lib_path}

    # init queues to store todo and completed variants
    TODO_Q = queue.Queue()
    DONE_Q = queue.Queue()

    # detect OS and select app name
    if platform.system() == 'Windows':
        PERF_APP = 'ipsec_perf.exe'
    else:
        PERF_APP = 'ipsec_perf'


def get_algos(type):
    """get algorithms from perf app output"""
    global PERF_APP

    cmd = [PERF_APP, '--{}-algo'.format(type) ]

    output = subprocess.run(cmd, stderr=subprocess.PIPE, \
                            env=ENVS, check=False).stderr.decode('utf-8')

    output = output.split(' ')
    return output[5:-1]


def parse_cores(core_str):
    """Parse core list passed through command line"""
    cores = []

    # remove spaces
    core_str.replace(" ", "")

    # check if not a range
    if '-' not in core_str:
        return list(map(int, core_str.strip().split(',')))

    # parse range e.g. 2-8
    core_str = core_str.strip().split('-')
    for i in range(int(core_str[0]), int(core_str[1]) + 1):
        cores.append(i)

    return cores


def parse_results(variants):
    """Parse output of perf app for variant"""
    out = []

    # set header
    lines = variants[0].get_output().split('\n')
    for line in lines[:-1]:
        out.append(line.split('\t')[0])

    # append output for all variants to single list
    for var in variants:
        lines = var.get_output().split('\n')
        for i in range(0, len(lines) - 1):
            out[i] += '\t{}'.format(lines[i].split()[1])

    return out


def run_test(core=None):
    """
    Main processing thread function
    1. Dequeue variants from todo queue until empty
    2. Run performance test for variant
    3. Place completed variants in completed (done) queue
    """
    global QUIET
    global TODO_Q
    global DONE_Q
    global EXIT_ERROR

    while TODO_Q.empty() is False:
        variant = TODO_Q.get()

        # skip if error encountered
        if EXIT_ERROR is True:
            if QUIET is False:
                print('{} {}'.format(variant.get_info(), '...skipped'), file=sys.stderr)
            TODO_Q.task_done()
            continue

        # set core if specified
        if core is not None:
            variant.set_core(core)

        # print variant information
        if QUIET is False:
            print(variant.get_info(), file=sys.stderr)

        # run variant
        if variant.run() is False:
            print('error encountered in run: {}...'\
                      .format(variant.get_cmd()), \
                      file=sys.stderr)
            EXIT_ERROR = True

        DONE_Q.put(variant)
        TODO_Q.task_done()


def parse_args():
    """Parse command line arguments"""
    global QUIET
    archs = ['SSE', 'AVX', 'AVX2', 'AVX512']
    cores = None
    directions = ['encrypt', 'decrypt']
    offset = 24
    alg_types = ['cipher-only', 'hash-only', 'aead-only']
    sizes = None

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description="Wrapper script for the ipsec-mb " \
                                     "performance application enabling extended functionality")

    # parse and validate args
    parser.add_argument("-a", "--arch", choices=archs, default=None, action='append',
                        help="set architecture to test (default is test all archs)")
    parser.add_argument("-c", "--cores", default=cores, help="list/range of cores e.g. 2-8 or 3,4,5")
    parser.add_argument("-d", "--direction", default=None,
                        choices=directions, help="Cipher direction")
    parser.add_argument("-o", "--offset", default=offset, type=int,
                        help="offset for the SHA size increment, default is 24")
    parser.add_argument("-t", "--alg-type", default=None, action='append', choices=alg_types,
                        help="algorithm types to test")
    parser.add_argument("-s", "--job-size", default=None,
                        help=textwrap.dedent('''\
                        size of the cipher & hash job in bytes.
                        It can be:
                           - single value: test single size
                           - list: test multiple sizes separated by commas
                           - range: test multiple sizes with following format
                             min:step:max (e.g. 16:16:256)\n'''))
    parser.add_argument("-q", "--quiet", default=False, action='store_true',
                        help="disable verbose output")

    args = parser.parse_args()

    # convert values where necessary
    if args.arch is not None:
        archs = args.arch

    if args.alg_type is not None:
        alg_types = args.alg_type

    if args.cores is not None:
        try:
            cores = parse_cores(args.cores)
        except:
            print("{}: error: argument -c/--cores: invalid value " \
                  "{}".format(sys.argv[0], args.cores), file=sys.stderr)
            sys.exit(1)

    if args.direction is not None:
        directions = [args.direction]

    if args.quiet is True:
        QUIET = True

    return archs, cores, directions, str(args.offset), alg_types, args.job_size

def main():
    """
    Main function to:
    - parse command line args
    - generate and enqueue list of variants to run
    - schedule variants across selected cores
    - post process results and print to stdout
    """
    global TOTAL_VARIANTS
    global QUIET
    global TODO_Q
    global DONE_Q
    global EXIT_ERROR

    header = '\n{0:<5} {1:<4} {2:<6} {3:<7} {4:<40}'\
        .format('NO', 'CORE', 'ARCH', 'DIR', 'ALG')
    result = [] # list to store parsed results
    cipher_algos = [] # list of cipher algorithms to run
    hash_algos = [] # list of hash algorithms to run
    aead_algos = [] # list of AEAD algorithms to run

    # init global vars
    init_vars()

    # parse command line  args
    archs, cores, directions, offset, alg_types, sizes = parse_args()

    # print args
    if QUIET is False:
        print('Testing:', file=sys.stderr)
        print('  Architectures: {}'.format(archs), file=sys.stderr)
        print('  Algorithms: {}'.format(alg_types), file=sys.stderr)
        print('  Directions: {}'.format(directions), file=sys.stderr)
        if offset is not None:
            print('  Offset: {}'.format(offset), file=sys.stderr)
        if sizes is not None:
            print('  Sizes: {}'.format(sizes), file=sys.stderr)
        if cores is not None:
            print('  Cores: {}'.format(cores), file=sys.stderr)
        print(header, file=sys.stderr)

    # get list of selected algorithms
    if 'cipher-only' in alg_types:
        cipher_algos = get_algos('cipher')
    if 'hash-only' in alg_types:
        hash_algos = get_algos('hash')
    if 'aead-only' in alg_types:
        aead_algos = get_algos('aead')

    # fill todo queue with variants to test
    for arch in archs:
        for direction in directions:
            for cipher_alg in cipher_algos:
                # skip low performing ciphers for now
                if 'des' in cipher_alg or 'kasumi' in cipher_alg:
                    continue
                TODO_Q.put(Variant(idx=TOTAL_VARIANTS, arch=arch, direction=direction, \
                                   offset=offset, sizes=sizes, cipher_alg=cipher_alg))
                TOTAL_VARIANTS += 1

        # skip direction for hash only algs
        for hash_alg in hash_algos:
            # skip low performing algorithms for now
            if 'kasumi' in hash_alg:
                continue
            TODO_Q.put(Variant(idx=TOTAL_VARIANTS, arch=arch, direction=None, \
                               offset=offset, sizes=sizes, hash_alg=hash_alg))
            TOTAL_VARIANTS += 1

        for direction in directions:
            for aead_alg in aead_algos:
                TODO_Q.put(Variant(idx=TOTAL_VARIANTS, arch=arch, direction=direction, \
                                   offset=offset, sizes=sizes, aead_alg=aead_alg))
                TOTAL_VARIANTS += 1

    # take starting timestamp
    start_ts = time.time()

    # If cores selected start a new thread on each core
    # otherwise start single thread without specifying a core
    #
    # Each thread takes a variant from the todo queue
    # and places it in the done queue when complete
    if cores is None:
        threading.Thread(target=run_test).start()
    else:
        for core in cores:
            threading.Thread(target=run_test, args=(core,)).start()

    # wait for all threads to complete
    TODO_Q.join()

    # take end timestamp
    end_ts = time.time()

    # exit if error encountered
    if EXIT_ERROR is True:
        print('Error encountered while running tests!', file=sys.stderr)
        sys.exit(1)

    # output time taken to complete
    runtime = end_ts - start_ts
    if QUIET is False:
        print("Time to complete: {:.3f} seconds" \
              .format(runtime), file=sys.stderr)

    # transfer completed runs from the
    # done queue to the results list
    while DONE_Q.empty() is False:
        variant = DONE_Q.get()
        result.append(variant)

    # sort by idx
    result.sort(key=lambda x: x.get_idx())

    # parse results and print to stdout
    output = parse_results(result)
    for line in output:
        print(line)

if __name__ == "__main__":
    main()

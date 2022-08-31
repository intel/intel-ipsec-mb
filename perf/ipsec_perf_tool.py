#!/usr/bin/env python3

"""
**********************************************************************
  Copyright(c) 2021-2022, Intel Corporation All rights reserved.

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
    def __init__(self, idx=None, arch=None, direction='encrypt', cipher_alg=None,
                 hash_alg=None, aead_alg=None, sizes=None, offset=None,
                 cold_cache=False, shani_off=False, force_job_api=False,
                 unhalted_cycles=False, quick_test=False, smoke_test=False,
                 imix=None, aad_size=None, job_iter=None, no_time_box=False):
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
        self.cold_cache = cold_cache
        self.shani_off = shani_off
        self.force_job_api = force_job_api
        self.unhalted_cycles = unhalted_cycles
        self.quick_test = quick_test
        self.smoke_test = smoke_test
        self.imix = imix
        self.aad_size = aad_size
        self.job_iter = job_iter
        self.no_time_box = no_time_box

        if self.arch is not None:
            self.cmd += ' --arch {}'.format(self.arch)

        if self.offset is not None:
            self.cmd += ' -o {}'.format(self.offset)

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

        if self.cold_cache is True:
            self.cmd += ' -c'

        if self.shani_off is True:
            self.cmd += ' --shani-off'

        if self.force_job_api is True:
            self.cmd += ' --force-job-api'

        if self.unhalted_cycles is True:
            self.cmd += ' --unhalted-cycles'

        if self.quick_test is True:
            self.cmd += ' --quick'

        if self.smoke_test is True:
            self.cmd += ' --smoke'

        if self.no_time_box is True:
            self.cmd += ' --no-time-box'
                
        if self.imix is not None:
            self.cmd += ' --imix {}'.format(self.imix)

        if self.aad_size is not None:
            self.cmd += ' --aad-size {}'.format(self.aad_size)

        if self.job_iter is not None:
            self.cmd += ' --job-iter {}'.format(self.job_iter)


    def run(self):
        """Run perf app and store output"""
        try:
            self.cmd_output = \
                subprocess.run(self.cmd, \
                               stdout=subprocess.PIPE, \
                               stderr=subprocess.PIPE, \
                               shell=True, env=ENVS, \
                               check=True).stdout.decode('utf-8')
            return True
        except subprocess.CalledProcessError as e:
            self.cmd_output = e.stderr.decode('utf-8')
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
        elif cipher_alg == '':
            hash_alg = self.hash_alg
        else:
            hash_alg = ' + ' + self.hash_alg

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


def init_global_vars():
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


def get_info():
    """get system and app info from perf app output"""
    global PERF_APP
    archs = None
    best_arch = None
    cipher_algos = None
    hash_algos = None
    aead_algos = None

    cmd = PERF_APP + ' --print-info'

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, \
                             stderr=subprocess.STDOUT, \
                             env=ENVS, shell=True, check=True)
        output = res.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print("Error (" + str(e.returncode) + ")")
        print(e.output.decode('utf-8'))
        sys.exit(1)

    lines = output.rstrip().split('\n')
    try:
        for line in lines:
            info = line.split(':')
            if info[0] == 'Supported architectures':
                archs = info[1].split()
            if info[0] == 'Best architecture':
                best_arch = info[1].split()
            if info[0] == 'Supported cipher algorithms':
                cipher_algos = info[1].split()
            if info[0] == 'Supported hash algorithms':
                hash_algos = info[1].split()
            if info[0] == 'Supported aead algorithms':
                aead_algos = info[1].split()
    except:
        print("Error parsing --print-info output:\n" \
              "{}".format(output), file=sys.stderr)

    if archs is None or best_arch is None or cipher_algos is None \
       or hash_algos is None or aead_algos is None:
        print("Error parsing system and app information", file=sys.stderr)
        sys.exit(1)

    return archs, best_arch, cipher_algos, hash_algos, aead_algos


def parse_cores(core_str):
    """Parse core list passed through command line"""
    num_cores = os.cpu_count()
    cores = []

    # remove spaces
    core_str.replace(" ", "")

    # check if not a range
    if '-' not in core_str:
        cores = list(map(int, core_str.strip().split(',')))
    else:
        # parse range e.g. 2-8
        core_str = core_str.strip().split('-')
        for i in range(int(core_str[0]), int(core_str[1]) + 1):
            cores.append(i)

    # ensure valid cores specified
    for core in cores:
        if core < 0 or core >= num_cores:
            print("Core {} out of range!".format(core), file=sys.stderr)
            raise Exception()

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


def parse_args():
    """Parse command line arguments"""
    global QUIET
    cores = None
    directions = ['encrypt', 'decrypt']
    offset = 24
    alg_types = ['cipher-only', 'hash-only', 'aead-only', 'cipher-hash-all']

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description="Wrapper script for the ipsec-mb " \
                                     "performance application enabling extended functionality")

    # parse and validate args
    parser.add_argument("-a", "--arch", choices=['SSE', 'AVX', 'AVX2', 'AVX512'],
                        default=None, action='append',
                        help="set architecture to test (default tests all supported archs)")
    parser.add_argument("-c", "--cores", default=cores,
                        help="list/range of cores e.g. 2-8 or 3,4,5")
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
    parser.add_argument("--cold-cache", default=False, action='store_true',
                        help="use cold cache, it uses warm as default")
    parser.add_argument("--arch-best", action='store_true',
                        help="detect available architectures and run only on the best one")
    parser.add_argument("--shani-off", action='store_true', help="don't use SHA extensions")
    parser.add_argument("--force-job-api", action='store_true',
                        help="use JOB API for algorithms supported through direct API (i.e. AES-GCM, chacha20-poly1305)")
    parser.add_argument("--unhalted-cycles", action='store_true',
                        help=textwrap.dedent('''\
                        measure using unhalted cycles (requires root).
                        Note: RDTSC is used by default'''))
    parser.add_argument("--quick", action='store_true',
                        help=textwrap.dedent('''\
                        reduces number of test iterations by x10
                        (less precise but quicker)'''))
    parser.add_argument("--smoke", action='store_true',
                        help=textwrap.dedent('''\
                        very quick, imprecise and without print out
                        (for validation only)'''))
    parser.add_argument("--imix", default=None,
                        help=textwrap.dedent('''\
                        set numbers that establish occurrence proportions between packet sizes.
                        It requires a list of sizes through --job-size.
                        (e.g. --imix 4,6 --job-size 64,128 will generate
                        a series of job sizes where on average 4 out of 10
                        packets will be 64B long and 6 out of 10 packets
                        will be 128B long)'''))
    parser.add_argument("--aad-size", default=None, type=int,
                        help="size of AAD for AEAD algorithms")
    parser.add_argument("--job-iter", default=None, type=int,
                        help="number of tests iterations for each job size")
    parser.add_argument("--no-time-box", default=False, action='store_true',
                        help="disables time box feature for single packet size test duration (100ms)")

    args = parser.parse_args()

    # validate and convert values where necessary
    if args.arch is not None and args.arch_best is True:
        print("{}: error: argument -a/--arch cannot be used with " \
              "--arch-best".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    if args.cores is not None:
        try:
            cores = parse_cores(args.cores)
        except:
            print("{}: error: argument -c/--cores: invalid value " \
                  "{}".format(sys.argv[0], args.cores), file=sys.stderr)
            sys.exit(1)

    if args.imix is not None and args.job_size is None:
        print("{}: error: argument --imix must be used with " \
              "--job-size".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    if args.alg_type is not None:
        alg_types = args.alg_type
    else:
        # strip all cipher hash combinations in default run
        alg_types = alg_types[:-1]

    if args.direction is not None:
        directions = [args.direction]

    if args.quiet is True:
        QUIET = True

    return args.arch, cores, directions, args.offset, \
        alg_types, args.job_size, args.cold_cache, args.arch_best, \
        args.shani_off, args.force_job_api, args.unhalted_cycles, \
        args.quick, args.smoke, args.imix, \
        args.aad_size, args.job_iter, args.no_time_box


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
            print('Error encountered running: {}\nOutput:\n{}'\
                  .format(variant.get_cmd(),
                          variant.get_output()),
                  file=sys.stderr)
            EXIT_ERROR = True

        DONE_Q.put(variant)
        TODO_Q.task_done()


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

    # init global vars
    init_global_vars()
    supported_archs, best_arch, cipher_algos, hash_algos, aead_algos = get_info()

    # parse command line args
    archs, cores, directions, offset, alg_types, sizes, cold_cache, arch_best, \
        shani_off, force_job_api, unhalted_cycles, quick_test, smoke_test, \
        imix, aad_size, job_iter, no_time_box = parse_args()

    # validate requested archs are supported
    if arch_best is True:
        archs = best_arch
    elif archs is None:
        archs = supported_archs
    else:
        for arch in archs:
            if arch not in supported_archs:
                print('Error: {} arch not supported!'.format(arch), file=sys.stderr)
                sys.exit(1)

    # print args
    if QUIET is False:
        print('Testing:', file=sys.stderr)
        print('  Architectures: {}'.format(archs), file=sys.stderr)
        print('  Algorithms: {}'.format(alg_types), file=sys.stderr)
        print('  Directions: {}'.format(directions), file=sys.stderr)
        if offset is not None:
            print('  Offset: {}'.format(offset), file=sys.stderr)
        if aad_size is not None:
            print('  AAD size: {}'.format(aad_size), file=sys.stderr)
        if sizes is not None:
            print('  Sizes: {}'.format(sizes), file=sys.stderr)
        if imix is not None:
            print('  IMIX: {}'.format(imix), file=sys.stderr)
        if cores is not None:
            print('  Cores: {}'.format(cores), file=sys.stderr)
        print('  Cache: {}'.format("cold" if cold_cache else "warm"), file=sys.stderr)
        print('  SHANI: {}'.format("off" if shani_off else "on"), file=sys.stderr)
        print('  API: {}'.format("job" if force_job_api else "direct"), file=sys.stderr)
        print('  Measuring using {}'.format("unhalted cycles" if unhalted_cycles \
                                            else "rdtsc"), file=sys.stderr)
        if quick_test is True or smoke_test is True:
            print('  Test type: {}'.format("smoke" if smoke_test else "quick"), file=sys.stderr)
        if job_iter is not None:
            print('  Job iterations: {}'.format(job_iter), file=sys.stderr)

        print(header, file=sys.stderr)

    # fill todo queue with variants to test
    for arch in archs:
        if 'cipher-only' in alg_types:
            for direction in directions:
                for cipher_alg in cipher_algos:
                    TODO_Q.put(Variant(idx=TOTAL_VARIANTS, arch=arch, direction=direction,
                                       offset=offset, sizes=sizes, cipher_alg=cipher_alg,
                                       cold_cache=cold_cache, shani_off=shani_off,
                                       force_job_api=force_job_api, unhalted_cycles=unhalted_cycles,
                                       quick_test=quick_test, smoke_test=smoke_test, imix=imix,
                                       aad_size=aad_size, job_iter=job_iter, no_time_box=no_time_box))
                    TOTAL_VARIANTS += 1

        if 'hash-only' in alg_types:
            # skip direction for hash only algs
            for hash_alg in hash_algos:
                TODO_Q.put(Variant(idx=TOTAL_VARIANTS, arch=arch, direction=None,
                                   offset=offset, sizes=sizes, hash_alg=hash_alg,
                                   cold_cache=cold_cache, shani_off=shani_off,
                                   force_job_api=force_job_api, unhalted_cycles=unhalted_cycles,
                                   quick_test=quick_test, smoke_test=smoke_test, imix=imix,
                                   aad_size=aad_size, job_iter=job_iter, no_time_box=no_time_box))
                TOTAL_VARIANTS += 1

        if 'aead-only' in alg_types:
            for direction in directions:
                for aead_alg in aead_algos:
                    TODO_Q.put(Variant(idx=TOTAL_VARIANTS, arch=arch, direction=direction,
                                       offset=offset, sizes=sizes, aead_alg=aead_alg,
                                       cold_cache=cold_cache, shani_off=shani_off,
                                       force_job_api=force_job_api, unhalted_cycles=unhalted_cycles,
                                       quick_test=quick_test, smoke_test=smoke_test, imix=imix,
                                       aad_size=aad_size, job_iter=job_iter, no_time_box=no_time_box))
                    TOTAL_VARIANTS += 1

        if 'cipher-hash-all' in alg_types:
            for direction in directions:
                # all cipher + hash combinations
                for cipher_alg in cipher_algos:
                    for hash_alg in hash_algos:
                        TODO_Q.put(Variant(idx=TOTAL_VARIANTS, arch=arch, direction=direction,
                                           offset=offset, sizes=sizes, cipher_alg=cipher_alg,
                                           hash_alg=hash_alg, cold_cache=cold_cache,
                                           shani_off=shani_off, force_job_api=force_job_api,
                                           unhalted_cycles=unhalted_cycles, quick_test=quick_test,
                                           smoke_test=smoke_test, imix=imix, aad_size=aad_size,
                                           job_iter=job_iter, no_time_box=no_time_box))
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

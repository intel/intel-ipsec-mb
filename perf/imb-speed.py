#!/usr/bin/env python3

"""
**********************************************************************
  Copyright(c) 2024, Intel Corporation All rights reserved.

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

import sys
import platform
import os
import queue
import threading
import subprocess

COL_WIDTH = 19
# number of variants to run
TOTAL_VARIANTS = 0
# dictionary to store env vars
ENVS = None
# queues to store todo and completed variants
TODO_Q = None
DONE_Q = None
# perf application name
PERF_APP = ''
# exit on error flag
EXIT_ERROR = False

class Variant:
    """Class to setup and run test case variant"""
    def __init__(self, idx=None, arch=None, direction='encrypt', cipher_alg=None,
                 hash_alg=None, aead_alg=None, sizes=None, time_box=3000,
                 throughput=None):
        """Build perf app command line"""
        global PERF_APP

        self.idx = idx
        self.arch = arch
        self.direction = direction
        self.cipher_alg = cipher_alg
        self.hash_alg = hash_alg
        self.aead_alg = aead_alg
        self.sizes = sizes
        self.cmd = '{} --no-progress-bar '.format(PERF_APP)
        self.cmd_output = ''
        self.out = []
        self.time_box = time_box
        self.throughput = throughput

        if self.arch is not None:
            self.cmd += ' --arch {}'.format(self.arch)

        if self.aead_alg is not None:
            self.cmd += ' --aead-algo {}'.format(self.aead_alg)

        if self.cipher_alg is not None:
            self.cmd += ' --cipher-algo {}'.format(self.cipher_alg)

        if self.hash_alg is not None:
            self.cmd += ' --hash-algo {}'.format(self.hash_alg)

        if self.cipher_alg is not None or \
           self.aead_alg is not None:
            self.cmd += ' --cipher-dir {}'.format(self.direction)

        if self.sizes is not None:
            self.cmd += ' --job-size {}'.format(self.sizes)

        if self.time_box is not None:
            self.cmd += ' --time-box {}'.format(self.time_box)
                
        if self.throughput is not None:
            self.cmd += ' --throughput'

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

def run_test(core=None):
    """
    Main processing thread function
    1. Run performance test for variant
    2. Place completed variants in completed (done) queue
    """
    
    global EXIT_ERROR

    while TODO_Q.empty() is False:
        variant = TODO_Q.get()

        # skip if error encountered
        if EXIT_ERROR is True:
            continue

        # set core if specified
        if core is not None:
            variant.set_core(core)

        # run variant
        if variant.run() is False:
            print('Error encountered running: {}\nOutput:\n{}'\
                    .format(variant.get_cmd(),
                            variant.get_output()),
                    file=sys.stderr)
            EXIT_ERROR = True

        DONE_Q.put(variant)
        TODO_Q.task_done()

class SpeedTool(object):
    """
    Main class
    """
    @staticmethod
    def usage():
        """
        Prints usage
        """
        print("This tool prints imb_perf throughput in openssl speed format.")
        print("Usage:")
        print("\timb-speed.py [-evp algo] [-bytes int] [-seconds int]\n")
        print("\t             [-arch arch] [-c/-cores mask]\n")
        print("\t-arch      - takes the architecture. default: best architecture")
        print("\t-bytes     - takes custom-sized buffer - single value, list or range.")
        print("\t             list: sizes separated by comma (e.g. 16,64,256)")
        print("\t             range: min:step:max (e.g. 16:16:256)")
        print("\t             default: 16, 64, 256, 1024, 8192, 16384")
        print("\t-seconds   - takes timebox in seconds. default: 3")
        print("\t-c/-cores  - takes list/range of cores e.g. 2-8 or 3,4,5. default: none")
        print("\t-decrypt   - time decryption instead of encryption")
        print("\t-evp       - takes algorithm")
        print("Example:")
        print("\timb-speed.py -evp aes-gcm-256 -bytes 16834 -seconds 3 -cores 2,4 -arch AVX512")

    def parse_cores(self, core_str):
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

    def parse_args(self):
        """
        Get commandline arguments
        """
        global ARCH
        global ALGO
        global PACKET_SIZE
        global TIMEBOX
        global CORES
        global DECRYPT

        ARCH = None
        ALGO = None
        PACKET_SIZE = "16,64,256,1024,8192,16384"
        TIMEBOX = 3000
        CORES = None
        DECRYPT = False

        for i in range(len(sys.argv)):
            arg = sys.argv[i]
            if arg == "-arch":
                if sys.argv[i+1]:
                    ARCH = sys.argv[i+1]
                else:
                    print("Please enter the architecture")
                    print("Default: AVX2, AVX512, SSE")
                    sys.exit(1)
            if arg == "-bytes":
                if sys.argv[i+1]:
                    PACKET_SIZE = sys.argv[i+1]
                else:
                    print("Please enter a single value, list or range for the packet sizes in bytes")
                    print("list: Sizes separated by comma, range: min:step:max (e.g. 16:16:256)")
                    print("Default: 16, 64, 256, 1024, 8192, 16384")
                    sys.exit(1)
            if arg == "-seconds":
                if sys.argv[i+1].isdigit():
                    TIMEBOX = int(sys.argv[i+1]) * 1000 # to ms
                else:
                    print("Please enter a number for the timebox in seconds")
                    print("Default: 3 seconds")
                    sys.exit(1)
            if arg == "-cores" or arg == "-c":
                if sys.argv[i+1]:
                    CORES = self.parse_cores(str(sys.argv[i+1]))
                else:
                    print("Please enter a list/range of cores")
                    print("Default: None")
                    sys.exit(1)
            if arg == "-evp":
                if sys.argv[i+1]:
                    ALGO = sys.argv[i+1]
                else:
                    print("Please enter the algorithm")
                    sys.exit(1)
            if arg == "-decrypt":
                DECRYPT = True
            if arg == "-h":
                self.usage()
                sys.exit(1)

    def get_info(self):
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


    def parse_results(self, variants):
        """Parse output of perf app for variant"""

        # Generate the list of sizes
        if ':' in PACKET_SIZE:
            min_val, step, max_val = map(int, PACKET_SIZE.split(':'))
            sizes = [str(size) for size in range(min_val, max_val + 1, step)]
        else:
            sizes = PACKET_SIZE.split(',')

        print("\n" + f"Type".ljust(COL_WIDTH+10)+" ".join(f"{j} bytes".ljust(COL_WIDTH) for j in sizes))

        # print throughput for all variants
        for var in variants:
            lines = var.get_output().split('\n')

            hash_alg = None
            cipher_alg = None
            key_size = None
            direction = None
            arch = None
            for line in lines:
                if line.startswith('ARCH'):
                    arch = line.split('\t')[1]
                if line.startswith('HASH_ALG'):
                    hash_alg = line.split('\t')[1]
                    alg = hash_alg
                if line.startswith('CIPHER'):
                    cipher_alg = line.split('\t')[1]
                    alg = cipher_alg
                if line.startswith('KEY_SIZE'):
                    key_size = line.split('\t')[1]

            if hash_alg is not None and not hash_alg.startswith("NULL"):
                alg = hash_alg
            if cipher_alg is not None and not cipher_alg.startswith("NULL"):
                alg = cipher_alg + " " + key_size
            
            alg = alg + " " + arch 

            values = {}
            time_in_seconds = TIMEBOX / 1000
            for line in lines:
                parts = line.split('\t')
                if parts[0] in sizes and parts[0] != '':
                    values[parts[0]] = round((float(parts[1]) / 1000) / time_in_seconds, 2) # Convert bytes to kilobytes per second

            print(f"{alg}".ljust(COL_WIDTH+10)+" ".join(f"{values[j]}k".ljust(COL_WIDTH) for j in sizes))

    def measure(self):
        """
        Measure function to:
        - generate and enqueue list of variants to run
        - schedule and run variants 
        """
        global TOTAL_VARIANTS
        global ENVS
        global TODO_Q
        global DONE_Q
        global PERF_APP

        result = [] # list to store parsed results

        # init vars
        TOTAL_VARIANTS = 0

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
            PERF_APP = 'imb-perf.exe'
        else:
            PERF_APP = 'imb-perf'
        
        # set directions
        directions = ['encrypt']
        if DECRYPT is True:
            directions = ['decrypt']

        supported_archs, best_arch, cipher_algos, hash_algos, aead_algos = self.get_info()

        if ARCH is None:
            archs = best_arch
        elif ARCH in supported_archs:
            archs = [ARCH]
        else:
            print('Supported architectures: {}'.format(', '.join(supported_archs)), file=sys.stderr)
            print('Unknown architecture: {}'.format(ARCH), file=sys.stderr)
            return result
        
        # print args
        print('Measuring:', file=sys.stderr)
        print('  Architecture: {}'.format(archs), file=sys.stderr)
        print('  Size(s): {}'.format(PACKET_SIZE), file=sys.stderr)
        if ALGO is not None:
            print('  Algo: {}'.format(ALGO), file=sys.stderr)
        else:
            print('  Algo: All', file=sys.stderr)
        if CORES is not None:
            print('  Cores: {}'.format(CORES), file=sys.stderr)
        if TIMEBOX is not None:
            print('  Timebox: {} seconds'.format(TIMEBOX/1000), file=sys.stderr)
        if DECRYPT is False:
            print('  Direction: encrypt', file=sys.stderr)
        else:
            print('  Direction: decrypt', file=sys.stderr)

        AEAD_ALGO = None
        HASH_ALGO = None
        CIPHER_ALGO = None
        # Determine the type of ALGO
        if ALGO is None:
            AEAD_ALGO = aead_algos
            HASH_ALGO = hash_algos
            CIPHER_ALGO = cipher_algos
        elif ALGO in aead_algos:
            AEAD_ALGO = [ALGO]
        elif ALGO in hash_algos:
            HASH_ALGO = [ALGO]
        elif ALGO in cipher_algos:
            CIPHER_ALGO = [ALGO]
        else:
            print('\nAEAD algorithms: {}'.format(', '.join(aead_algos)), file=sys.stderr)
            print('\nHash/digest algorithms: {}'.format(', '.join(hash_algos)), file=sys.stderr)
            print('\nCipher algorithms: {}'.format(', '.join(cipher_algos)), file=sys.stderr)
            print('\nUnknown algorithm: {}'.format(ALGO), file=sys.stderr)
            return result

        for arch in archs:
            if HASH_ALGO is not None:
                for algo in HASH_ALGO:
                    TODO_Q.put(Variant(idx=TOTAL_VARIANTS, arch=arch, direction=None,
                                    sizes=PACKET_SIZE, hash_alg=algo, time_box=TIMEBOX,
                                    throughput=True))
                    TOTAL_VARIANTS += 1
            if AEAD_ALGO is not None:
                for direction in directions:
                    for algo in AEAD_ALGO:
                        TODO_Q.put(Variant(idx=TOTAL_VARIANTS, arch=arch, direction=direction,
                                        sizes=PACKET_SIZE, aead_alg=algo, time_box=TIMEBOX,
                                        throughput=True))
                        TOTAL_VARIANTS += 1
            if CIPHER_ALGO is not None:
                for direction in directions:
                    for algo in CIPHER_ALGO:
                        TODO_Q.put(Variant(idx=TOTAL_VARIANTS, arch=arch, direction=direction,
                                        sizes=PACKET_SIZE, cipher_alg=algo, time_box=TIMEBOX,
                                        throughput=True))
                        TOTAL_VARIANTS += 1
        
        # If cores selected start a new thread on each core
        # otherwise start single thread without specifying a core
        #
        # Each thread takes a variant from the todo queue
        # and places it in the done queue when complete
        if CORES is None:
            threading.Thread(target=run_test).start()
        else:
            for core in CORES:
                threading.Thread(target=run_test, args=(core,)).start()
        
        # wait for all threads to complete
        TODO_Q.join()

        # transfer completed runs from the
        # done queue to the results list
        while DONE_Q.empty() is False:
            variant = DONE_Q.get()
            result.append(variant)

        # sort by idx
        result.sort(key=lambda x: x.get_idx())

        return result

    def run(self):
        """
        Main method
        """

        # parse command line arguments
        self.parse_args()

        # measure performance
        results = self.measure()

        # parse and print results
        if len(results) > 0:
            self.parse_results(results)

if __name__ == '__main__':
    SpeedTool().run()


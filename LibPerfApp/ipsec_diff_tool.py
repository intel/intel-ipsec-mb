#!/usr/bin/env python

"""
**********************************************************************
  Copyright(c) 2017 Intel Corporation All rights reserved.

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

# Number of parameters (ARCH, CIPHER_MODE, DIR, HASH_ALG, KEY_SIZE)
PAR_NUM = 5

class Variant(object):
    """
    Class representing one test including chosen parameters and
    results of average execution times
    """
    def __init__(self, **args):
        self.arch = args['arch']
        self.cipher_mode = args['cipher']
        self.cipher_dir = args['dir']
        self.hash_alg = args['alg']
        self.key_size = args['keysize']
        self.avg_times = []
        self.lin_func = ()

    def set_times(self, avg_times):
        """
        Fills test execution time list
        """
        self.avg_times = avg_times

    def lin_reg(self, sizes):
        """
        Computes linear regression of set of coordinates (x,y)
        """

        n = len(sizes)

        if n != len(self.avg_times):
            print "Error!"
            return None

        sumx = sum(sizes)
        sumy = sum(self.avg_times)
        sumxy = sum([x * y for x, y in zip(sizes, self.avg_times)])
        sumsqrx = sum([pow(x, 2) for x in sizes])
        a = (n * sumxy - sumx * sumy) / float(n * sumsqrx - pow(sumx, 2))
        b = (sumy - a * sumx) / float(n)

        # Linear function representation y=ax+b
        self.lin_func = (a, b)

class Parser(object):
    """
    Class used to parse a text file contaning performance data
    """

    def __init__(self):
        pass

    @staticmethod
    def convert2int(in_tuple):
        """
        Converts a tuple of strings into a list of integers
        """

        result = list(in_tuple)             # Converting to list
        result = [int(i) for i in result]   # Converting str to int
        return result

    def load(self):
        """
        Reads a text file by columns, stores data in objects
        for further comparision of performance
        """

        v_list = []
        # Reading by columns, results in list of tuples
        # Each tuple is representing a column from a text file
        cols = zip(*(line.strip().split('\t') for line in sys.stdin))

        # Reading first column with payload sizes, ommiting first 5 rows
        sizes = self.convert2int(cols[0][PAR_NUM:])
        print "Available buffer sizes:\n"
        print sizes
        print "========================================================"
        print "\n\nVariants:\n"

        # Reading remaining columns contaning performance data
        for row in cols[1:]:
            # First rows are run options
            arch, c_mode, c_dir, h_alg, key_size = row[:PAR_NUM]
            print arch, c_mode, c_dir, h_alg, key_size

            # Getting average times
            avg_times = self.convert2int(row[PAR_NUM:])
            print avg_times
            print "------"

            # Putting new object to the result list
            v_list.append(Variant(arch=arch, cipher=c_mode, dir=c_dir,
                                  alg=h_alg, keysize=key_size))
            v_list[-1].set_times(avg_times)
            # Finding linear function representation of data set
            v_list[-1].lin_reg(sizes)
            print v_list[-1].lin_func
            print "============\n"
        return v_list, sizes

class DiffTool(object):
    """
    Main class
    """

    def __init__(self):
        pass


    def run(self):
        """
        Main method
        """
        parser = Parser()
        obj, sz = parser.load()

if __name__ == '__main__':
    DiffTool().run()

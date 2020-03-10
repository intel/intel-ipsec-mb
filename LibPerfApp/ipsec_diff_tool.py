#!/usr/bin/env python

"""
**********************************************************************
  Copyright(c) 2017-2020, Intel Corporation All rights reserved.

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
        self.params = (args['arch'], args['cipher'], args['dir'], args['alg'],
                       args['keysize'])

        self.avg_times = []
        self.slope = None
        self.intercept = None

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
        self.slope = (n * sumxy - sumx * sumy) / float(n * sumsqrx - pow(sumx, 2))
        self.intercept = (sumy - self.slope * sumx) / float(n)

    def get_params_str(self):
        """
        Returns all parameters concatenated into one string
        """
        return "\t".join(i for i in self.params)

    def get_lin_func_str(self):
        """
        Returns string having linear coefficients
        """
        slope = "{:.5f}".format(self.slope)
        intercept = "{:.5f}".format(self.intercept)
        return "{}\t{}".format(slope, intercept)

class VarList(list):
    """
    Class used to store all test variants as a list of objects
    """

    def find_obj(self, params):
        """
        Finds first occurence of object containing given parameters
        """
        ret_val = None
        matches = (obj for obj in self if obj.params == params)
        try:
            ret_val = next(matches)
        except StopIteration:
            pass
        return ret_val

    def compare(self, list_b, tolerance):
        """
        Finds variants from two data sets which are matching and compares
        its linear regression coefficients.
        Compares list_b against itself.
        """

        if tolerance is None:
            tolerance = 5.0
        if tolerance < 0.0:
            print "Bad argument: Tolerance must not be less than 0%"
            exit(1)
        print "TOLERANCE: {:.2f}%".format(tolerance)

        warning = False
        print "NO\tARCH\tCIPHER\tDIR\tHASH\tKEYSZ\tSLOPE A\tINTERCEPT A\tSLOPE B\tINTERCEPT B"
        for i, obj_a in enumerate(self):
            obj_b = list_b.find_obj(obj_a.params)
            if obj_b != None:
                if obj_a.slope < 0.0:
                    obj_a.slope = 0
                if obj_b.slope < 0.0:
                    obj_b.slope = 0
                slope_bv = 0.01 * tolerance * obj_a.slope # border value
                intercept_bv = 0.01 * tolerance * obj_a.intercept
                diff_slope = obj_b.slope - obj_a.slope
                diff_intercept = obj_b.intercept - obj_a.intercept
                if (obj_a.slope > 0.001 and obj_b.slope > 0.001 and
                        diff_slope > slope_bv) or diff_intercept > intercept_bv:
                    warning = True
                    print "{}\t{}\t{}\t{}".format(i + 1,
                                                  obj_b.get_params_str(),
                                                  obj_a.get_lin_func_str(),
                                                  obj_b.get_lin_func_str())
        if not warning:
            print "No differences found."
        return warning

    def printout(self):
        """
        Prints out readable representation of the list
        """

        print "NO\tARCH\tCIPHER\tDIR\tHASH\tKEYSZ\tSLOPE \tINTERCEPT"
        for i, obj in enumerate(self):
            print "{}\t{}\t{}".format(i + 1,
                                      obj.get_params_str(),
                                      obj.get_lin_func_str())



class Parser(object):
    """
    Class used to parse a text file contaning performance data
    """

    def __init__(self, fname, verbose):
        self.fname = fname
        self.verbose = verbose

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

        v_list = VarList()
        # Reading by columns, results in list of tuples
        # Each tuple is representing a column from a text file
        try:
            f = open(self.fname, 'r')
        except IOError:
            print "Error reading {} file.".format(self.fname)
            exit(1)
        else:
            with f:
                cols = zip(*(line.strip().split('\t') for line in f))

        # Reading first column with payload sizes, ommiting first 5 rows
        sizes = self.convert2int(cols[0][PAR_NUM:])
        if self.verbose:
            print "Available buffer sizes:\n"
            print sizes
            print "========================================================"
            print "\n\nVariants:\n"

        # Reading remaining columns contaning performance data
        for row in cols[1:]:
            # First rows are run options
            arch, c_mode, c_dir, h_alg, key_size = row[:PAR_NUM]
            if self.verbose:
                print arch, c_mode, c_dir, h_alg, key_size

            # Getting average times
            avg_times = self.convert2int(row[PAR_NUM:])
            if self.verbose:
                print avg_times
                print "------"

            # Putting new object to the result list
            v_list.append(Variant(arch=arch, cipher=c_mode, dir=c_dir,
                                  alg=h_alg, keysize=key_size))
            v_list[-1].set_times(avg_times)
            # Finding linear function representation of data set
            v_list[-1].lin_reg(sizes)
            if self.verbose:
                print "({}, {})".format(v_list[-1].slope, v_list[-1].intercept)
                print "============\n"
        return v_list, sizes

class DiffTool(object):
    """
    Main class
    """

    def __init__(self):
        self.fname_a = None
        self.fname_b = None
        self.tolerance = None
        self.verbose = False
        self.analyze = False

    @staticmethod
    def usage():
        """
        Prints usage
        """
        print "This tool compares file_b against file_a printing out differences."
        print "Usage:"
        print "\tipsec_diff_tool.py [-v] [-a] file_a file_b [tol]\n"
        print "\t-v - verbose"
        print "\t-a - takes only one argument: name of the file to analyze"
        print "\tfile_a, file_b - text files containing output from ipsec_perf tool"
        print "\ttol - tolerance [%], must be >= 0, default 5\n"
        print "Examples:"
        print "\tipsec_diff_tool.py file01.txt file02.txt 10"
        print "\tipsec_diff_tool.py -a file02.txt"
        print "\tipsec_diff_tool.py -v -a file01.txt"


    def parse_args(self):
        """
        Get commandline arguments
        """
        if len(sys.argv) < 3 or sys.argv[1] == "-h":
            self.usage()
            exit(1)
        if sys.argv[1] == "-a":
            self.analyze = True
            self.fname_a = sys.argv[2]
        elif sys.argv[2] == "-a":
            if sys.argv[1] == "-v":
                self.verbose = True
            self.analyze = True
            self.fname_a = sys.argv[3]
        elif sys.argv[1] == "-v":
            self.verbose = True
            self.fname_a = sys.argv[2]
            self.fname_b = sys.argv[3]
            if len(sys.argv) >= 5:
                self.tolerance = float(sys.argv[4])

        else:
            self.fname_a = sys.argv[1]
            self.fname_b = sys.argv[2]
            if len(sys.argv) >= 4:
                self.tolerance = float(sys.argv[3])

    def run(self):
        """
        Main method
        """
        self.parse_args()

        parser_a = Parser(self.fname_a, self.verbose)
        list_a, sizes_a = parser_a.load()

        if not self.analyze:
            parser_b = Parser(self.fname_b, self.verbose)
            list_b, sizes_b = parser_b.load()
            if sizes_a != sizes_b:
                print "Error. Buffer size lists in two compared " \
                        "data sets differ! Aborting.\n"
                exit(1)
            warning = list_a.compare(list_b, self.tolerance) # Compares list_b against list_a
            if warning:
                exit(2)
        else:
            list_a.printout() # Takes only one file and prints it out

if __name__ == '__main__':
    DiffTool().run()

#*****************************************************************************
#  Copyright (c) 2021-2022, Intel Corporation
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#      * Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of Intel Corporation nor the names of its contributors
#        may be used to endorse or promote products derived from this software
#        without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# *****************************************************************************
import os, re

LIB_PATH = "../lib/"
LIB_NAME = "libIPSec_MB.so"
LIB_HEADER = "intel-ipsec-mb.h"
COMMON_TOP_LINES = "direct_api_param_test.c_template"

INVALID_FUN_NAME_STR = "invalid function name"
INVALID_STRUCT_NAME_STR = "invalid structure name"
TEMP_FILE_NAME = "raw_direct_api_param_test.c"

MAX_BUFFS = 17

len_limits_per_fun = { "IMB_AES128_GCM_ENC": "((1ULL << 39) - 256)",
                       "IMB_AES192_GCM_ENC": "((1ULL << 39) - 256)",
                       "IMB_AES256_GCM_ENC": "((1ULL << 39) - 256)",
                       "IMB_AES128_GCM_DEC": "((1ULL << 39) - 256)",
                       "IMB_AES192_GCM_DEC": "((1ULL << 39) - 256)",
                       "IMB_AES256_GCM_DEC": "((1ULL << 39) - 256)",
                       "IMB_AES128_GCM_ENC_UPDATE" : "((1ULL << 39) - 256)",
                       "IMB_AES192_GCM_ENC_UPDATE" : "((1ULL << 39) - 256)",
                       "IMB_AES256_GCM_ENC_UPDATE" : "((1ULL << 39) - 256)",
                       "IMB_AES128_GCM_DEC_UPDATE" : "((1ULL << 39) - 256)",
                       "IMB_AES192_GCM_DEC_UPDATE" : "((1ULL << 39) - 256)",
                       "IMB_AES256_GCM_DEC_UPDATE" : "((1ULL << 39) - 256)"
                    }
fixed_start = """struct test_suite_context ts;
    int errors = 0, run = 0;\n
    #ifndef DEBUG\n#if defined(__linux__)
    sighandler_t handler;
    #else\nvoid *handler;\n#endif\n#endif
    printf("Extended Invalid Direct API arguments test:");
    test_suite_start(&ts, "INVALID-ARGS");
    #ifndef DEBUG\nhandler = signal(SIGSEGV, seg_handler);
    \n#endif\nif ((mb_mgr->features&IMB_FEATURE_SAFE_PARAM)==0) {
    printf("SAFE_PARAM feature disabled, skipping remaining tests");
    goto dir_api_exit;\n}"""

fixed_end_main = """test_suite_update(&ts, run - errors, errors);
    dir_api_exit:
    errors = test_suite_end(&ts);
    #ifndef DEBUG\nsignal(SIGSEGV, handler);\n#endif
    return errors;\n}\n
"""

def ERR(err_str):
    print("ERROR: {}".format(err_str))

# This searches for patterns in header file and returns dict with results
# Functions works only for 3 args exactly
# lines     :   list of all lines from LIB_HEADER
# keyword   :   position of keyword in pattern (0/1/2)
# list_arg  :   arg1 arg2 or arg3 arg will be split by "," and stored
#               as list
# val       :   arg1 arg2 or arg3
def parse_header_file(lines, pattern, keyword, list_arg, val):
    match_dict = {}
    new_lines = " ".join(lines)
    compiled_pattern = re.compile(pattern)
    matches = compiled_pattern.findall(new_lines)
    for match in matches:
        nice_arg_list = match[list_arg].replace("\\", "").strip(",").split(",")
        nicer_arg_list = []
        for arg in nice_arg_list: nicer_arg_list.append(arg.strip())
        match_dict[match[keyword]] = (match[val], nicer_arg_list)
    return match_dict

# Finds all prototypes for functions from header file and returns
# dict with fields in format:
#   function_type : (return_value, list_of_args)
#       eg parsed line:
#           "typedef int (*des_keysched_t)(uint64_t *, const void *);"
#       will be in returned dict:
#           "des_keysched_t" : ("int", ["uint64_t *", "const void *"])
# lines: list of all lines from LIB_HEADER (split by "\n")
def find_prototypes(lines):
    typedef_pattern = "typedef (.*?).[(][*](.*?)[)].*?[(](.*?)[)];"
    (val, keyword, list_arg) = (0, 1, 2)
    return parse_header_file(lines, typedef_pattern, keyword, list_arg, val)

# Finds all function definitions from header file and returns
# dict with fields in format: function_name : (funct_define, list_of_args)
# eg parsed line:
#   "#define IMB_KASUMI_KEY_SCHED_SIZE(_mgr)((_mgr)->kasumi_key_sched_size())"
# will be in returned dict:
# "kasumi_key_sched_size" : ("IMB_KASUMI_KEY_SCHED_SIZE", [])
# lines: list of all lines from LIB_HEADER (split by "\n")
def get_IMB_FUN_DEFINES(lines):
    define_pattern = "define (.*?)[(]_mgr(.*?)[)].*?[(]_mgr[)]->(.*?)[(]"
    (val, list_arg, keyword) = (0, 1, 2)
    return parse_header_file(lines, define_pattern, keyword, list_arg, val)

# Finds function types and names available in IMB_MGR structure
# lines: list of all lines from LIB_HEADER (split by "\n")
def get_IMB_MGR_struct_fields(lines):
    struct_name = INVALID_STRUCT_NAME_STR
    struct_IMB_MGR = []
    for line in lines:
        struct_line = re.match("typedef struct IMB_MGR {", line)
        if line == "} IMB_MGR;" : return struct_IMB_MGR
        elif struct_line        : struct_name = "IMB_MGR"
        elif struct_name == "IMB_MGR":
            # single line field if format is "(spaces) (type) (name);"
            field = re.match("(.*) (.*);", line.strip())
            if field:
                (field_type, field_name) = field.groups()
                struct_IMB_MGR.append((field_name.strip(), field_type.strip()))
    return struct_IMB_MGR

def check_cipher(algo_name):
    if ( "ENC" in algo_name or "DEC" in algo_name or
         "F8" in algo_name or "EEA" in algo_name):
        return True
    return False

def check_auth(algo_name):
    if ( "F9" in algo_name or "EIA" in algo_name or
         "GHASH" in algo_name or "UIA" in algo_name):
        return True
    return False

# Check if there is a need to declare valid arg in function
# If there is only 1 arg and its replaced with invalid value
# in test vector there is no need to declare it.
def arg_needed(arg_name, test_vector_list, fun):
    if arg_name == "i": return True
    if fun in test_vectors_per_function:
        for test_vector in test_vectors_per_function[fun]:
            for arg_n in test_vector:
                if arg_n.strip("_") == arg_name:
                    return True
    return False

def arg_declare(arg_type, name, arg_range, val):
    line = arg_type + " " + name + arg_range
    if val != "":
        line += " = " + val
    line += ";"
    return line

# Generate lines in function that declare and initialize
# valid and invalid arguments.
# Return list of lines to be included in function definition
def declare_args(arg_list, test_vectors, fun):
    (args_def, for_loop_copies) = ([], [])
    new_arg_list = [("unsigned ", "_i")]
    new_arg_list.extend(arg_list)

    for (arg_type, arg_name) in new_arg_list:
        (pts, brackets) = (arg_type.count("*"), arg_type.count("["))
        (n_name, val, a_len) = (arg_name.strip("_"), "", "")
        n_type = arg_type.replace("void", "uint8_t") \
                           .replace("*", "").replace("[", "").replace("]", "")
        if arg_needed(n_name, test_vectors, fun):
            if pts + brackets == 1:
                if brackets > 0 or "len" in n_name: 
                    (values, a_len) = ([], "[MAX_BUFFS]")
                    for i in range(MAX_BUFFS): values.append("1")
                    val = "{" + ", ".join(values) + "}"
                    if pts > 0:
                        new_val = val.replace("1","0")
                        args_def.append(n_type + " " + n_name +
                                        "_all_zero [MAX_BUFFS] = " \
                                        + new_val + ";")
                elif 'uint' in n_type: a_len = "[BUFF_SIZE]"
                else: # struct declaration
                    args_def.append(n_type + " " + n_name + "_s;")
                    (val, n_name) =  ("&" + n_name + "_s", "*" + n_name)
            elif pts + brackets == 0:
                if "count" in n_name: val = "MAX_BUFFS"
                else:                 val = "1"
            elif pts + brackets > 1:
                n_type = n_type.replace("const", "").strip()
                v_type = n_type.replace("uint8_t", "void")
                p_name = "*" + n_name
                a_len = "[MAX_BUFFS][BUFF_SIZE]"
                if arg_type[0:5] == "const"     : v_type = "const " + v_type
                if arg_type.count("const") == 2 : n_type = "const " + n_type
                for_loop_copies.append(n_name + "[i] = "+n_name+"_s[i];")
                for_loop_copies.append(n_name + "_NULL_pts[i]" + " = NULL;")
                n_name = n_name + "_s"
                args_def.append(arg_declare(v_type, p_name, "[MAX_BUFFS]",
                                            val))
                args_def.append(arg_declare(v_type, p_name + "_NULL_pts",
                                            "[MAX_BUFFS]", val))
            line = arg_declare(n_type, n_name, a_len, val)
            args_def.append(line)

    args_def.append("int seg_err; /* segfault flag */\n")
    args_def.append("seg_err = setjmp(dir_api_param_env);")
    args_def.append("if (seg_err) {")
    args_def.append('printf("%s: segfault occurred!", __func__);')
    args_def.append("return 1;\n}")

    # initialize arrays of pts
    if len(for_loop_copies) > 0:
        args_def.append("\nfor (i = 0; i < MAX_BUFFS; i++){")
        for pair in for_loop_copies: args_def.append(pair)
        args_def.append("}")
    return args_def

# Create list of lines with code for each test function
def create_test_functions(full_data, test_vectors_per_function):
    fn_list = []
    fn_lines = []
    for fun, val in full_data.items():
        fn_lines.append("/*\n* @brief Performs direct API invalid param tests for {} */".format(fun))
        fn_lines.append("static int test_{}(struct IMB_MGR *mgr) {{".format(fun))
        fn_lines.extend(declare_args(val["args"], test_vectors_per_function, fun))
        fn_lines.append("\nstruct fn_args {")
        args_for_fn_call = ""
        for (arg_type, arg_name) in val["args"]:
            new_arg_name = arg_name.strip("_")
            new_arg_type = arg_type.replace("[]", "*")
            fn_lines.append("{} {};".format(new_arg_type, new_arg_name))
            args_for_fn_call += "ap->{}, ".format(new_arg_name)
        args_for_fn_call = args_for_fn_call.strip().strip(",")
        fn_lines.append("const IMB_ERR exp_err;")
        test_line = "} fn_args[] = {"
        if fun in test_vectors_per_function:
            for test_vector in test_vectors_per_function[fun]:
                if "fn_args" not in test_line: test_line += ","
                fn_lines.append(test_line)
                test_line = "{"
                for arg_n in test_vector:
                    if test_line != "{": test_line += ","
                    test_line += arg_n.strip("_")
                test_line += "}"
            fn_lines.append(test_line)
        fn_lines.append("};\n")
        fn_lines.append("/* Iterate over args */")
        fn_lines.append("for (i = 0; i < DIM(fn_args); i++) {")
        fn_lines.append("const struct fn_args *ap = &fn_args[i];\n")
        fn_lines.append("{}(mgr, {});".format(fun,args_for_fn_call))
        fn_lines.append('if (unexpected_err(mgr, ap->exp_err, "{}"))'.format(fun))
        fn_lines.append("return 1; }")
        fn_lines.append("return 0; }\n")
        fn_list.append("errors += test_{}(mb_mgr);".format(fun))
        fn_list.append("run ++;\n")
    return (fn_lines, fn_list)

# Check if its possible to pass invalid value for given parameter
def is_always_valid(simplified_arg_n, fun):
    always_valid_exceptions = { "KASUMI" : ["IV", "DIR"],
                                "SHA" : ["LENGTH"],
                                "GMAC_UPDATE" : ["LEN"],
                                "AES128_CFB_ONE" : ["LEN"],
                                "CRC" : ["LEN"],
                                "CHACHA" : ["LEN"],
                                "GCM_INIT": ["AADL"],
                                "GCM_ENC": ["AADL"],
                                "GCM_DEC": ["AADL"],
                                "CHACHA20_POLY1305_INIT": ["AADL"]}
    for algo_key, list_of_args in always_valid_exceptions.items():
        if algo_key in fun and simplified_arg_n.strip("_") in list_of_args:
            return True
    if simplified_arg_n == "_COUNT" or simplified_arg_n == "_OFFSET":
        return True
    return False

# Main logic to pick correct error code for invalid value of argument
# Error codes are matched to arguments by argument name
def assign_errors_to_inv_parameters_by_arg_name(full_data):
    test_cases = {}
    direct_api_errors = [ "IMB_ERR_NULL_SRC", "IMB_ERR_NULL_DST",
                      "IMB_ERR_NULL_KEY", "IMB_ERR_NULL_EXP_KEY",
                      "IMB_ERR_NULL_IV", "IMB_ERR_NULL_AUTH",
                      "IMB_ERR_NULL_AAD", "IMB_ERR_CIPH_LEN",
                      "IMB_ERR_AUTH_LEN", "IMB_ERR_IV_LEN",
                      "IMB_ERR_KEY_LEN", "IMB_ERR_AUTH_TAG_LEN",
                      "IMB_ERR_AAD_LEN", "IMB_ERR_SRC_OFFSET",
                      "IMB_ERR_NULL_AUTH_KEY", "IMB_ERR_NULL_CTX" ]
    for fun, val in full_data.items():
        test_cases[fun] = []
        for (arg_t, arg_n) in val["args"]:
            simplified_arg_n = re.sub(r'\d+', '', arg_n).upper()
            simplified_arg_n = simplified_arg_n.replace("_ENC", "")
            simplified_arg_n = simplified_arg_n.replace("_DEC", "")
            err_name = ""
            err_val = ""
            if is_always_valid(simplified_arg_n, fun):
                err_name = "ALWAYS VALID"
                err_val = "0"
            elif arg_t.count("*") == 2 or (arg_t.count("*") == 1 and "[" in arg_t):
                err_val = "{}_NULL_pts".format(arg_n)
                err_name_test = "IMB_ERR_NULL" + simplified_arg_n
                if err_name_test in direct_api_errors:
                    err_name = err_name_test
                elif "TAG" in simplified_arg_n:
                    err_name = "IMB_ERR_NULL_AUTH"
            elif arg_t.count("*") == 1:
                err_name_test = "IMB_ERR_NULL" + simplified_arg_n
                if err_name_test in direct_api_errors:
                    err_name = err_name_test
                    err_val = "NULL"
                elif "TAG" in simplified_arg_n:
                    err_name = "IMB_ERR_NULL_AUTH"
                    err_val = "NULL"
                else:
                    err_val = simplified_arg_n.lower().strip("_") + "_all_zero"
                    if check_cipher(fun): err_name = "IMB_ERR_CIPH_LEN"
                    elif check_auth(fun): err_name = "IMB_ERR_AUTH_LEN"
            elif "_LEN" in simplified_arg_n or simplified_arg_n[len(simplified_arg_n)-1] == "L":
                arg_name = simplified_arg_n.strip("L")
                arg_name = arg_name.replace("_LEN", "")
                err_name_test = "IMB_ERR{}_LEN".format(arg_name)
                err_val = "0"
                if err_name_test in direct_api_errors: err_name = err_name_test
                elif "TAG" in simplified_arg_n: err_name = "IMB_ERR_AUTH_TAG_LEN"
                elif check_auth(fun):           err_name = "IMB_ERR_AUTH_LEN"
                elif check_cipher(fun):         err_name = "IMB_ERR_CIPH_LEN"
                if fun in len_limits_per_fun:
                    err_val = len_limits_per_fun[fun]
            if err_name == "" : ERR("Unrecognized argument: {} {}".format(arg_t, arg_n))
            else: test_cases[fun].append((arg_t, arg_n, err_name, err_val))
    return test_cases

# Make connections between function prototypes and definitions
def prep_func_arg_type_matches(function_list_from_mgr, defines, prototypes):
    full_data = {}
    for (function, f_type) in function_list_from_mgr:
        if function not in defines:
            ERR("No IMB_ define for {}".format(function))
        elif f_type not in prototypes:
            ERR ("No prototype for {}".format(f_type))
        else:
            (fun_name, args) = defines[function]
            (ret_val, arg_types) = prototypes[f_type]
            if len(args) != len(arg_types):
                ERR ("Prototype and definition does not match:")
                ERR ("{} : {} ".format(fun_name, args))
                ERR ("{} : {} ".format(f_type, arg_types))
            if len(args) == 0:
                print ("Skipping {} - no args to be tested".format(fun_name))
            merged_args = []
            if len(args) != len(arg_types):
                ERR("\nargs:{} \narg_types:{}".format(", ".join(args), ", ".join(arg_types)))
            else: 
                for i in range(len(args)):
                    if arg_types[i] != 'void' or args[i] != '':
                        merged_args.append((arg_types[i].strip(), args[i].strip()))
            if len(args) > 1:
                full_data[fun_name] = {
                    "ret_val" : ret_val,
                    "args" : merged_args
                }
    return full_data

if __name__ == "__main__":
    # --------------------------------------------------------------------------
    # Parse intel-ipsec-mb.h
    with open("{}{}".format(LIB_PATH, LIB_HEADER), "r") as header_file:
        header_lines = header_file.read().split('\n')

    if header_lines:
        prototypes = find_prototypes(header_lines)
        imb_struct = get_IMB_MGR_struct_fields(header_lines)
        defines = get_IMB_FUN_DEFINES(header_lines)
    else:
         ERR ("Reading header file failed")
         exit(-1)

    function_list = []
    # fields from IMB_MGR that are not functions to be tested in param check test
    fn_exclude_list = [ "earliest_job", "next_job", "jobs[IMB_MAX_JOBS]",
                        "flags", "features", "reserved[5]", "used_arch",
                        "imb_errno", "get_next_job", "submit_job",
                        "submit_job_nocheck", "get_completed_job", "flush_job",
                        "queue_size" ]
    for (name, f_type) in imb_struct:
        # exclude ooo functions and some basic fields
        if "_ooo" not in name and name not in fn_exclude_list:
            function_list.append((name, f_type))

    # --------------------------------------------------------------------------
    # Match arg types with arg names and args with invalid values
    full_data = prep_func_arg_type_matches(function_list, defines, prototypes)
    test_cases = assign_errors_to_inv_parameters_by_arg_name(full_data)

    # --------------------------------------------------------------------------
    # Generate list of test vectors
    test_vectors_per_function = {}
    for function, val in test_cases.items():
        test_vectors = []
        standard_args = []
        for i in range(0, len(val)):
            (arg_t, arg_n, error, error_val) = val[i]
            standard_args.append(arg_n.strip("_"))
        for i in range(0, len(val)):
            (arg_t, arg_n, error, error_val) = val[i]
            if error != "ALWAYS VALID":
                args_replaced = standard_args.copy()
                args_replaced[i] = error_val
                args_replaced.append(error)
                test_vectors.append(args_replaced)
                if "_NULL_pts" in error_val:
                    new_args_replaced = standard_args.copy()
                    new_args_replaced[i] = "NULL"
                    new_args_replaced.append(error)
                    test_vectors.append(new_args_replaced)
        if len(test_vectors) > 0:
            test_vectors_per_function[function] = test_vectors

    # --------------------------------------------------------------------------
    # Generate direct api invalid params test file
    c_file_lines = ["/" + "*" * 77]
    c_file_lines.append(" * This file is generated by {}. ".format(__file__) + \
                         "Do not change it manually")
    c_file_lines.append("*"*77 + "/")
    c_file_lines.append("")


    # fixed lines from header file
    test_file_start = []
    with open("{}".format(COMMON_TOP_LINES), "r") as start_file:
        test_file_start = start_file.read().split('\n')
    for line in test_file_start:
        c_file_lines.append(line)

    # create test_IMB_MGR_(func name){(...)} per each function
    (fn_lines, fn_list) =  create_test_functions(full_data, test_vectors_per_function)
    c_file_lines.extend(fn_lines)

    c_file_lines.append("int direct_api_param_test(struct IMB_MGR *mb_mgr){")
    c_file_lines.extend(fixed_start.splitlines())
    c_file_lines.extend(fn_list)
    c_file_lines.extend(fixed_end_main.splitlines())

    with open(TEMP_FILE_NAME, "w") as raw:
        raw.write("\n".join(c_file_lines))

    # --------------------------------------------------------------------------
    # Format generated file
    # Base clang format is from 
    # https://github.com/intel/intel-cmt-cat/blob/master/.clang-format
    # Options added to it so it would comply with IPSec style
    clang_format_args = []
    with open(".clang-format", "r") as clang_format:
        clang_format_args = clang_format.read().split('\n')

    clang_cmd = "clang-format -style=\"{" + ", ".join(clang_format_args) + \
                "}\" " + TEMP_FILE_NAME + " > direct_api_param_test.c"
    os.system(clang_cmd)
    os.system("rm " + TEMP_FILE_NAME)
    # --------------------------------------------------------------------------


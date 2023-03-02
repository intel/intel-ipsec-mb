#
# Copyright (c) 2012-2023, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Intel Corporation nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

TEST_APP := test-app
XVALID_APP := xvalid-app
FUZZ_APP := fuzz-app
ACVP_APP := acvp-app
WYCHEPROOF_APP := wycheproof-app

# targets come here
all: $(TEST_APP) $(XVALID_APP) $(FUZZ_APP) $(ACVP_APP) $(WYCHEPROOF_APP)

.PHONY: $(TEST_APP) $(XVALID_APP) $(FUZZ_APP) $(ACVP_APP) $(WYCHEPROOF_APP)

$(TEST_APP):
	$(MAKE) -C test-app

$(XVALID_APP):
	$(MAKE) -C xvalid-app

$(FUZZ_APP):
	$(MAKE) -C fuzz-app

$(ACVP_APP):
	$(MAKE) -C acvp-app

$(WYCHEPROOF_APP):
	$(MAKE) -C wycheproof-app

.PHONY: clean
clean:
	$(MAKE) -C test-app clean
	$(MAKE) -C xvalid-app clean
	$(MAKE) -C fuzz-app clean
	$(MAKE) -C acvp-app clean
	$(MAKE) -C wycheproof-app clean

# style check section
CHECKPATCH?=checkpatch.pl
CHECKPATCH_FLAGS = --no-tree --no-signoff --emacs --no-color --max-line-length=100 --ignore CODE_INDENT,INITIALISED_STATIC,LEADING_SPACE,SPLIT_STRING,UNSPECIFIED_INT,ARRAY_SIZE,BLOCK_COMMENT_STYLE,GLOBAL_INITIALISERS,AVOID_EXTERNS,COMPLEX_MACRO,USE_FUNC,CONSTANT_COMPARISON,MISSING_SPACE,NEW_TYPEDEFS

%.c_style_check : %.c
	$(CHECKPATCH) $(CHECKPATCH_FLAGS) -f $<

%.h_style_check : %.h
	$(CHECKPATCH) $(CHECKPATCH_FLAGS) -f $<

%.asm_style_check : %.asm
	$(CHECKPATCH) $(CHECKPATCH_FLAGS) -f $<

%.inc_style_check : %.inc
	$(CHECKPATCH) $(CHECKPATCH_FLAGS) -f $<

TEST_APP_SOURCES := $(wildcard $(TEST_APP)/*.[ch])
FUZZ_APP_SOURCES := $(wildcard $(FUZZ_APP)/*.[ch])
ACVP_APP_SOURCES := $(wildcard $(ACVP_APP)/*.[ch])
WYCHEPROOF_APP_SOURCES := $(wildcard $(WYCHEPROOF_APP)/*.[ch])
XVALID_APP_SOURCES := $(wildcard $(XVALID_APP)/*.[ch]) \
		      $(wildcard $(XVALID_APP)/*.asm) \
		      $(wildcard $(XVALID_APP)/*.inc)
SOURCES_ALL := $(TEST_APP_SOURCES) $(XVALID_APP_SOURCES) \
	       $(FUZZ_APP_SOURCES) $(ACVP_APP_SOURCES) $(WYCHEPROOF_APP_SOURCES)
SOURCES_STYLE := $(foreach infile,$(SOURCES_ALL),$(infile)_style_check)

.PHONY: style
style: $(SOURCES_STYLE)

# cppcheck analysis check
CPPCHECK ?= cppcheck
CPPCHECK_OPTS ?= -I./ -I../lib
CPPCHECK_FLAGS ?= -j $(shell getconf _NPROCESSORS_ONLN)
CPPCHECK_FLAGS1 ?= --cppcheck-build-dir=.cppcheck $(CPPCHECK_FLAGS)
CPPCHECK_FLAGS2 ?= --cppcheck-build-dir=.bughunt $(CPPCHECK_FLAGS)
.PHONY: cppcheck
cppcheck:
	mkdir -p .cppcheck
	$(CPPCHECK) --force --enable=all $(CPPCHECK_FLAGS1) $(CPPCHECK_OPTS) \
		./test-app ./xvalid-app ./fuzz-app ./acvp-app ./wycheproof-app

.PHONY: bughunt
bughunt:
	mkdir -p .bughunt
	$(CPPCHECK) --bug-hunting --inconclusive $(CPPCHECK_FLAGS2) $(CPPCHECK_OPTS) \
		./test-app ./xvalid-app ./fuzz-app ./acvp-app ./wycheproof-app


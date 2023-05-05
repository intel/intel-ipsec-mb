#
# Copyright (c) 2023, Intel Corporation
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

BURST_APP := burst-app

# targets come here
all: $(BURST_APP)

.PHONY: $(BURST_APP)

$(BURST_APP):
	$(MAKE) -C burst-app
.PHONY: clean
clean:
	$(MAKE) -C burst-app clean

# style check section
CHECKPATCH?=checkpatch.pl
CHECKPATCH_FLAGS = --no-tree --no-signoff --emacs --no-color --max-line-length=100 --ignore CODE_INDENT,INITIALISED_STATIC,LEADING_SPACE,SPLIT_STRING,UNSPECIFIED_INT,ARRAY_SIZE,BLOCK_COMMENT_STYLE,GLOBAL_INITIALISERS,AVOID_EXTERNS,COMPLEX_MACRO,USE_FUNC,CONSTANT_COMPARISON,MISSING_SPACE,NEW_TYPEDEFS

%.c_style_check : %.c
	$(CHECKPATCH) $(CHECKPATCH_FLAGS) -f $<

BURST_APP_SOURCES := $(wildcard $(BURST_APP)/*.[c])
SOURCES_ALL := $(BURST_APP_SOURCES)
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
		./burst-app

.PHONY: bughunt
bughunt:
	mkdir -p .bughunt
	$(CPPCHECK) --bug-hunting --inconclusive $(CPPCHECK_FLAGS2) $(CPPCHECK_OPTS) \
		./burst-app

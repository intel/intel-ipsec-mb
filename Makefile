#
# Copyright (c) 2020-2023, Intel Corporation
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

.PHONY: all clean style install uninstall help TAGS

all:
	$(MAKE) -C lib
	$(MAKE) -C test
	$(MAKE) -C perf
	$(MAKE) -C examples

clean:
	$(MAKE) -C lib clean
	$(MAKE) -C test clean
	$(MAKE) -C perf clean
	$(MAKE) -C examples clean

style:
	$(MAKE) -C lib style
	$(MAKE) -C test style
	$(MAKE) -C perf style
	$(MAKE) -C examples style

install:
	$(MAKE) -C lib install

uninstall:
	$(MAKE) -C lib uninstall

help:
	$(MAKE) -C lib help

doxy:
	$(MAKE) -C lib doxy

.PHONY: TAGS
TAGS:
	find ./ -name "*.[ch]" -print | etags -
	find ./ -name '*.asm'  | etags -a -
	find ./ -name '*.inc'  | etags -a -

# Check spelling in the code with codespell.
# See https://github.com/codespell-project/codespell for more details.
# Codespell options explained:
# -d        -- disable colours (emacs colours it anyway)
# -L        -- List of words to be ignored
# -S <skip> -- skip file types
# -I FILE   -- File containing words to be ignored
#
CODESPELL ?= codespell
CS_IGNORE_WORDS ?= iinclude,struc,fo,ue,od,ba,padd

.PHONY: spellcheck
spellcheck:
	$(CODESPELL) -d -L $(CS_IGNORE_WORDS) \
	-S "*.obj,*.o,*.a,*.so,*.lib,*~,*.so,*.so.*,*.d,imb-perf" \
	-S "imb-kat,imb-xvalid" \
	./lib ./perf ./test README.md SECURITY.md CONTRIBUTING \
	Makefile win_x64.mak ReleaseNotes.txt LICENSE $(CS_EXTRA_OPTS)

# cppcheck analysis check
cppcheck:
	$(MAKE) -C lib cppcheck
	$(MAKE) -C test cppcheck
	$(MAKE) -C perf cppcheck
	$(MAKE) -C examples cppcheck

# cppcheck bughunt analysis check
bughunt:
	$(MAKE) -C lib bughunt
	$(MAKE) -C test bughunt
	$(MAKE) -C perf bughunt
	$(MAKE) -C examples bughunt

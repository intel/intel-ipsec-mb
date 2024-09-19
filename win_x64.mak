#
# Copyright (c) 2020-2024, Intel Corporation
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

!if !defined(BUILD_DIR)
BUILD_DIR = build
!endif

all: warning
	cd lib & $(MAKE) /f win_x64.mak

clean:
	cd lib & $(MAKE) /f win_x64.mak clean

install:
	cd lib & $(MAKE) /f win_x64.mak install

uninstall:
	cd lib & $(MAKE) /f win_x64.mak uninstall

help:
	cd lib & $(MAKE) /f win_x64.mak help

# build cmake project
build-cmake:
	cmake -Ax64 -B $(BUILD_DIR)
	cmake --build $(BUILD_DIR) --config Release

# clean cmake project
clean-cmake:
	cmake --build $(BUILD_DIR) --target clean

warning:
	@echo "NOTE: Building the project with Makefiles is deprecated since v2.0 (replaced by CMake)."
	@echo "      Starting from v2.0, only the library can be built using Makefiles and not the applications."
	@echo "      See INSTALL.md for instructions to build the library and applications using CMake."
	@echo ""

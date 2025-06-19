/*****************************************************************************
 Copyright (c) 2021-2024, Intel Corporation

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

/**
 * @brief Measure TSC for set number of cycles
 *
 * @param cycles Number of iterations to run fixed cost loop with
 *               1-cycle latency dependency on all non-ancient CPUs
 *
 * @return Number of TSC cycles measured while in fixed cost loop
 */
uint64_t
measure_tsc(const uint64_t cycles);

/**
 * See the following links for more information about SSC marks:
 * https://community.intel.com/t5/Intel-ISA-Extensions/Merging-DCFG-regions-in-SDE-when-using-start-stop-ssc-mark/m-p/1232096
 * https://www.intel.com/content/www/us/en/developer/articles/technical/pintool-regions.html
 * https://github.com/WebAssembly/design/issues/1344
 */

/**
 * @brief Issue SSC mark 4
 */
void
ssc_mark4(void);

/**
 * @brief Issue SSC mark 5
 */
void
ssc_mark5(void);

/**
 * @brief Issue SSC mark 6
 */
void
ssc_mark6(void);

/**
 * @brief Issue SSC mark 7
 */
void
ssc_mark7(void);

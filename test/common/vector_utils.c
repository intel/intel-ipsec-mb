/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include "vector_utils.h"
#include "mac_test.h"
#include "cipher_test.h"

/**
 * @brief Record a parse error reason and errno for reporting at the `err` label.
 *
 * @param [out] out_reason receives the error description string
 * @param [out] out_errnum receives the errno value (0 if none)
 * @param [in]  reason     human-readable description of the failure
 * @param [in]  en         errno value, or 0 if not applicable
 */
static void
set_parse_error(const char **out_reason, int *out_errnum, const char *reason, const int en)
{
        *out_reason = reason;
        *out_errnum = en;
}

typedef enum {
        JSON_TOK_UNDEFINED = 0,
        JSON_TOK_OBJECT = 1,
        JSON_TOK_ARRAY = 2,
        JSON_TOK_STRING = 3,
        JSON_TOK_PRIMITIVE = 4
} json_tok_type;

enum json_parse_err { JSON_PARSE_NOMEM = -1, JSON_PARSE_INVAL = -2, JSON_PARSE_PART = -3 };

/**
 * @brief Map tokenizer error codes to readable diagnostics.
 *
 * @param [in] parse_status JSON tokenizer status code
 *
 * @return Description string for parse_status.
 */
static const char *
json_parse_err_to_reason(const int parse_status)
{
        switch (parse_status) {
        case JSON_PARSE_NOMEM:
                return "tokenizer ran out of token storage";
        case JSON_PARSE_INVAL:
                return "invalid JSON syntax";
        case JSON_PARSE_PART:
                return "incomplete JSON document";
        default:
                return "unknown tokenizer error";
        }
}

/**
 * @brief Print a structured JSON vector parsing error message.
 *
 * @param [in] path JSON file path
 * @param [in] stage Parsing stage/function where failure occurred
 * @param [in] reason Human-readable reason string
 * @param [in] errnum Optional errno value (0 when not applicable)
 * @param [in] parse_status Optional JSON parser status (<0 when applicable)
 * @param [in] tg_idx Test-group index (zero-based, -1 if unavailable)
 * @param [in] test_idx Test index within group (zero-based, -1 if unavailable)
 * @param [in] tcid Optional tcId pointer, NULL when unavailable
 */
static void
json_report_parse_error(const char *path, const char *stage, const char *reason, const int errnum,
                        const int parse_status, const int tg_idx, const int test_idx,
                        const size_t *tcid)
{
        fprintf(stderr, "JSON parse error: file=\"%s\", stage=\"%s\", reason=\"%s\"",
                (path != NULL) ? path : "(null)", (stage != NULL) ? stage : "unknown-stage",
                (reason != NULL) ? reason : "unknown-reason");

        if (errnum != 0)
                fprintf(stderr, ", errno=%d (%s)", errnum, strerror(errnum));
        if (parse_status < 0)
                fprintf(stderr, ", parse_status=%d", parse_status);
        if (tg_idx >= 0)
                fprintf(stderr, ", testGroup=%d", tg_idx + 1);
        if (test_idx >= 0)
                fprintf(stderr, ", test=%d", test_idx + 1);
        if (tcid != NULL)
                fprintf(stderr, ", tcId=%zu", *tcid);
        fprintf(stderr, "\n");
}

typedef struct {
        json_tok_type type; /**< Token type */
        int start;          /**< Inclusive start offset in JSON text */
        int end;            /**< Exclusive end offset in JSON text */
        int size;           /**< Number of direct child tokens */
} json_tok;

struct json_parse_state {
        const char *json; /**< Pointer to JSON document text */
        size_t len;       /**< Length of JSON document text */
        size_t pos;       /**< Current parser cursor */
        json_tok *tokens; /**< Output token array */
        size_t token_cnt; /**< Number of tokens emitted */
        size_t token_cap; /**< Capacity of output token array */
};

struct test_json_alloc_ctx {
        void **ptrs;    /**< Owned allocations to release on teardown */
        size_t ptr_cnt; /**< Number of tracked pointers */
        size_t ptr_cap; /**< Capacity of pointer tracking table */
};

/**
 * @brief Track an allocated pointer in the JSON allocation context.
 *
 * @param [in,out] ctx Allocation context
 * @param [in] ptr Pointer to track
 *
 * @return Operation status.
 * @retval 0 Pointer tracked successfully.
 * @retval -1 Pointer tracking table reallocation failed.
 */
static int
alloc_ctx_add_ptr(struct test_json_alloc_ctx *ctx, void *ptr)
{
        if (ctx->ptr_cnt < ctx->ptr_cap) {
                ctx->ptrs[ctx->ptr_cnt++] = ptr;
                return 0;
        }

        void **new_ptrs = realloc(ctx->ptrs, (ctx->ptr_cap + 32) * sizeof(void *));
        if (new_ptrs == NULL)
                return -1;

        ctx->ptrs = new_ptrs;
        ctx->ptr_cap += 32;
        ctx->ptrs[ctx->ptr_cnt++] = ptr;

        return 0;
}

/**
 * @brief Allocate memory and register it in the JSON allocation context.
 *
 * @param [in,out] ctx Allocation context
 * @param [in] sz Requested allocation size in bytes
 *
 * @return Allocated pointer.
 * @retval NULL Allocation failed.
 */
static void *
alloc_ctx_alloc(struct test_json_alloc_ctx *ctx, size_t sz)
{
        void *ptr;

        if (sz == 0)
                sz = 1;

        ptr = malloc(sz);
        if (ptr == NULL)
                return NULL;

        if (alloc_ctx_add_ptr(ctx, ptr) < 0) {
                free(ptr);
                return NULL;
        }

        return ptr;
}

/**
 * @brief Release all memory tracked by a JSON allocation context.
 *
 * @param [in] ctx_ptr Allocation context returned by vector load functions
 */
void
json_free_test_ctx(struct test_json_alloc_ctx *ctx)
{
        if (ctx == NULL)
                return;

        for (size_t i = 0; i < ctx->ptr_cnt; i++)
                free(ctx->ptrs[i]);

        free(ctx->ptrs);
        free(ctx);
}

/**
 * @brief Append one token to the parser output.
 *
 * @param [in,out] state Parser state
 * @param [in] type Token type to append
 * @param [in] start Inclusive start offset in JSON text
 * @param [in] end Exclusive end offset in JSON text
 *
 * @return Token index on success or parser error code on failure.
 */
static int
json_push_token(struct json_parse_state *state, const json_tok_type type, const int start,
                const int end)
{
        json_tok *token;

        if (state->token_cnt >= state->token_cap)
                return JSON_PARSE_NOMEM;

        token = &state->tokens[state->token_cnt++];
        token->type = type;
        token->start = start;
        token->end = end;
        token->size = 0;

        return (int) (state->token_cnt - 1);
}

/**
 * @brief Advance parser cursor past JSON whitespace.
 *
 * @param [in,out] state Parser state
 */
static void
json_skip_ws(struct json_parse_state *state)
{
        while (state->pos < state->len && isspace((unsigned char) state->json[state->pos]) != 0)
                state->pos++;
}

/**
 * @brief Check whether a character is a hexadecimal digit.
 *
 * @param [in] c Character to test
 *
 * @return Test result.
 * @retval 1 Character is hexadecimal.
 * @retval 0 Character is not hexadecimal.
 */
static int
json_is_hex_char(const char c)
{
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/**
 * @brief Parse one JSON string value and emit a JSON_TOK_STRING token.
 *
 * @param [in,out] state Parser state
 *
 * @return Token index on success or parser error code on failure.
 * @retval JSON_PARSE_PART Unterminated JSON string.
 * @retval JSON_PARSE_INVAL Invalid string escape or control character.
 * @retval JSON_PARSE_NOMEM No free slot in token array.
 */
static int
json_parse_string_token(struct json_parse_state *state)
{
        const size_t start = state->pos + 1;
        int tok_idx;

        state->pos++;

        while (state->pos < state->len) {
                char c = state->json[state->pos];

                if (c == '"') {
                        tok_idx = json_push_token(state, JSON_TOK_STRING, (int) start,
                                                  (int) state->pos);
                        if (tok_idx < 0)
                                return tok_idx;
                        state->pos++;
                        return tok_idx;
                }

                if ((unsigned char) c < 0x20)
                        return JSON_PARSE_INVAL;

                if (c == '\\') {
                        state->pos++;
                        if (state->pos >= state->len)
                                return JSON_PARSE_PART;

                        c = state->json[state->pos];
                        switch (c) {
                        case '"':
                        case '\\':
                        case '/':
                        case 'b':
                        case 'f':
                        case 'n':
                        case 'r':
                        case 't':
                                break;
                        case 'u':
                                if (state->pos + 4 >= state->len)
                                        return JSON_PARSE_PART;
                                if (!json_is_hex_char(state->json[state->pos + 1]) ||
                                    !json_is_hex_char(state->json[state->pos + 2]) ||
                                    !json_is_hex_char(state->json[state->pos + 3]) ||
                                    !json_is_hex_char(state->json[state->pos + 4]))
                                        return JSON_PARSE_INVAL;
                                state->pos += 4;
                                break;
                        default:
                                return JSON_PARSE_INVAL;
                        }
                }

                state->pos++;
        }

        return JSON_PARSE_PART;
}

/**
 * @brief Parse one JSON primitive value and emit a JSON_TOK_PRIMITIVE token.
 *
 * @param [in,out] state Parser state
 *
 * @return Token index on success or parser error code on failure.
 * @retval JSON_PARSE_INVAL Invalid primitive token.
 * @retval JSON_PARSE_NOMEM No free slot in token array.
 */
static int
json_parse_primitive_token(struct json_parse_state *state)
{
        const size_t start = state->pos;

        while (state->pos < state->len) {
                const char c = state->json[state->pos];

                if (c == ',' || c == ']' || c == '}' || isspace((unsigned char) c) != 0)
                        break;

                if ((unsigned char) c < 0x20 || (unsigned char) c >= 0x7f)
                        return JSON_PARSE_INVAL;

                state->pos++;
        }

        if (state->pos == start)
                return JSON_PARSE_INVAL;

        return json_push_token(state, JSON_TOK_PRIMITIVE, (int) start, (int) state->pos);
}

static int
json_parse_value_token(struct json_parse_state *state, int *out_idx);

/**
 * @brief Parse one JSON array value and all nested elements.
 *
 * @param [in,out] state Parser state
 *
 * @return Token index on success or parser error code on failure.
 * @retval JSON_PARSE_PART Unterminated array.
 * @retval JSON_PARSE_INVAL Invalid array syntax.
 * @retval JSON_PARSE_NOMEM No free slot in token array.
 */
static int
json_parse_array_token(struct json_parse_state *state)
{
        int array_idx;

        array_idx = json_push_token(state, JSON_TOK_ARRAY, (int) state->pos, -1);
        if (array_idx < 0)
                return array_idx;

        state->pos++;
        json_skip_ws(state);

        if (state->pos >= state->len)
                return JSON_PARSE_PART;

        if (state->json[state->pos] == ']') {
                state->tokens[array_idx].end = (int) (state->pos + 1);
                state->pos++;
                return array_idx;
        }

        /* Parse comma-separated array elements until the closing ']' token. */
        for (;;) {
                int val_idx;

                const int status = json_parse_value_token(state, &val_idx);
                if (status < 0)
                        return status;
                (void) val_idx;

                state->tokens[array_idx].size++;
                json_skip_ws(state);

                if (state->pos >= state->len)
                        return JSON_PARSE_PART;

                if (state->json[state->pos] == ',') {
                        state->pos++;
                        json_skip_ws(state);
                        continue;
                }

                if (state->json[state->pos] == ']') {
                        state->tokens[array_idx].end = (int) (state->pos + 1);
                        state->pos++;
                        return array_idx;
                }

                return JSON_PARSE_INVAL;
        }
}

/**
 * @brief Parse one JSON object value and all nested key/value pairs.
 *
 * @param [in,out] state Parser state
 *
 * @return Token index on success or parser error code on failure.
 * @retval JSON_PARSE_PART Unterminated object.
 * @retval JSON_PARSE_INVAL Invalid object syntax.
 * @retval JSON_PARSE_NOMEM No free slot in token array.
 */
static int
json_parse_object_token(struct json_parse_state *state)
{
        int obj_idx;

        obj_idx = json_push_token(state, JSON_TOK_OBJECT, (int) state->pos, -1);
        if (obj_idx < 0)
                return obj_idx;

        state->pos++;
        json_skip_ws(state);

        if (state->pos >= state->len)
                return JSON_PARSE_PART;

        if (state->json[state->pos] == '}') {
                state->tokens[obj_idx].end = (int) (state->pos + 1);
                state->pos++;
                return obj_idx;
        }

        /* Parse comma-separated object members as key/value pairs. */
        for (;;) {
                int key_idx;
                int val_idx;

                if (state->json[state->pos] != '"')
                        return JSON_PARSE_INVAL;

                key_idx = json_parse_string_token(state);
                if (key_idx < 0)
                        return key_idx;

                json_skip_ws(state);
                if (state->pos >= state->len)
                        return JSON_PARSE_PART;
                if (state->json[state->pos] != ':')
                        return JSON_PARSE_INVAL;

                state->pos++;
                json_skip_ws(state);

                const int status = json_parse_value_token(state, &val_idx);
                if (status < 0)
                        return status;
                (void) val_idx;

                state->tokens[key_idx].size = 1;
                state->tokens[obj_idx].size++;

                json_skip_ws(state);
                if (state->pos >= state->len)
                        return JSON_PARSE_PART;

                if (state->json[state->pos] == ',') {
                        state->pos++;
                        json_skip_ws(state);
                        continue;
                }

                if (state->json[state->pos] == '}') {
                        state->tokens[obj_idx].end = (int) (state->pos + 1);
                        state->pos++;
                        return obj_idx;
                }

                return JSON_PARSE_INVAL;
        }
}

/**
 * @brief Parse one JSON value token and return the root token index.
 *
 * @param [in,out] state Parser state
 * @param [out] out_idx Root token index for parsed value
 *
 * @return Operation status.
 * @retval 0 Value parsed successfully.
 * @retval JSON_PARSE_PART Incomplete input.
 * @retval JSON_PARSE_INVAL Invalid JSON value syntax.
 * @retval JSON_PARSE_NOMEM No free slot in token array.
 */
static int
json_parse_value_token(struct json_parse_state *state, int *out_idx)
{
        int tok_idx;

        json_skip_ws(state);
        if (state->pos >= state->len)
                return JSON_PARSE_PART;

        /* Dispatch parsing based on the first non-whitespace character. */
        switch (state->json[state->pos]) {
        case '{':
                tok_idx = json_parse_object_token(state);
                break;
        case '[':
                tok_idx = json_parse_array_token(state);
                break;
        case '"':
                tok_idx = json_parse_string_token(state);
                break;
        default:
                tok_idx = json_parse_primitive_token(state);
                break;
        }

        if (tok_idx < 0)
                return tok_idx;

        *out_idx = tok_idx;
        return 0;
}

/**
 * @brief Tokenize a complete JSON document.
 *
 * @param [in] json JSON document text
 * @param [in] len JSON document length in bytes
 * @param [out] tokens Output token array
 * @param [in] token_cap Output token array capacity
 *
 * @return Number of emitted tokens or parser error code.
 * @retval JSON_PARSE_PART Incomplete input.
 * @retval JSON_PARSE_INVAL Invalid JSON syntax.
 * @retval JSON_PARSE_NOMEM Output token array too small.
 */
static int
json_tokenize_document(const char *json, const size_t len, json_tok *tokens, const size_t token_cap)
{
        struct json_parse_state state = {
                .json = json,
                .len = len,
                .pos = 0,
                .tokens = tokens,
                .token_cnt = 0,
                .token_cap = token_cap,
        };
        int root_idx;

        json_skip_ws(&state);
        const int status = json_parse_value_token(&state, &root_idx);
        if (status < 0)
                return status;

        /* Reject trailing content and enforce the first emitted token as root. */
        json_skip_ws(&state);
        if (state.pos != state.len)
                return JSON_PARSE_INVAL;
        if (root_idx != 0)
                return JSON_PARSE_INVAL;

        return (int) state.token_cnt;
}

/**
 * @brief Return the token index immediately after the token subtree at idx.
 *
 * @param [in] tokens Token array
 * @param [in] idx Root token index of subtree
 *
 * @return Token index immediately after subtree.
 */
static int
json_token_skip(const json_tok *tokens, const int idx)
{
        int pos = idx + 1;

        for (int i = 0; i < tokens[idx].size; i++)
                pos = json_token_skip(tokens, pos);

        return pos;
}

/**
 * @brief Compare a JSON string token with a null-terminated C string.
 *
 * @param [in] json JSON document text
 * @param [in] token Token to compare
 * @param [in] str Null-terminated reference string
 *
 * @return Comparison result.
 * @retval 1 String token matches str.
 * @retval 0 String token does not match str.
 */
static int
json_token_eq(const char *json, const json_tok *token, const char *str)
{
        const int tok_len = token->end - token->start;
        const int str_len = (int) strlen(str);

        if (token->type != JSON_TOK_STRING)
                return 0;

        if (tok_len != str_len)
                return 0;

        return strncmp(json + token->start, str, str_len) == 0;
}

/**
 * @brief Find a key inside one JSON object token and return its value token index.
 *
 * @param [in] json JSON document text
 * @param [in] tokens Token array
 * @param [in] token_cnt Number of tokens in tokens
 * @param [in] obj_idx Object token index
 * @param [in] key Requested object key
 *
 * @return Value token index for key.
 * @retval -1 Key not found or invalid input.
 */
static int
json_object_get(const char *json, const json_tok *tokens, const int token_cnt, const int obj_idx,
                const char *key)
{
        int pos;
        int obj_end;

        if (obj_idx < 0 || obj_idx >= token_cnt)
                return -1;

        if (tokens[obj_idx].type != JSON_TOK_OBJECT)
                return -1;

        obj_end = tokens[obj_idx].end;
        pos = obj_idx + 1;
        /* Iterate over key/value token pairs inside the selected object subtree. */
        while (pos + 1 < token_cnt) {
                const int key_idx = pos;
                const int val_idx = pos + 1;

                if (tokens[key_idx].start < 0 || tokens[key_idx].end > obj_end ||
                    tokens[val_idx].start < 0 || tokens[val_idx].end > obj_end)
                        break;

                if (json_token_eq(json, &tokens[key_idx], key))
                        return val_idx;

                pos = json_token_skip(tokens, val_idx);
        }

        return -1;
}

/**
 * @brief Resolve a member from test-case scope, then test-group scope.
 *
 * @param [in] json JSON document text
 * @param [in] tokens Token array
 * @param [in] token_cnt Number of tokens in tokens
 * @param [in] tc_obj Test-case object token index
 * @param [in] tg_obj Test-group object token index
 * @param [in] key Requested member key
 *
 * @return Value token index for key.
 * @retval -1 Key not found in either scope.
 */
static int
json_member_with_fallback(const char *json, const json_tok *tokens, const int token_cnt,
                          const int tc_obj, const int tg_obj, const char *key)
{
        int idx = json_object_get(json, tokens, token_cnt, tc_obj, key);

        if (idx >= 0)
                return idx;

        return json_object_get(json, tokens, token_cnt, tg_obj, key);
}

/**
 * @brief Parse an unsigned decimal JSON primitive into size_t.
 *
 * @param [in] json JSON document text
 * @param [in] token Primitive token holding decimal digits
 * @param [out] out Parsed numeric value
 *
 * @return Operation status.
 * @retval 0 Value parsed successfully.
 * @retval -1 Invalid token format.
 */
static int
json_parse_size_t(const char *json, const json_tok *token, size_t *out)
{
        char num_buf[64];
        int len;
        char *end = NULL;
        unsigned long long val;

        if (token->type != JSON_TOK_PRIMITIVE)
                return -1;

        len = token->end - token->start;
        if (len <= 0 || len >= (int) sizeof(num_buf))
                return -1;

        memcpy(num_buf, json + token->start, len);
        num_buf[len] = '\0';

        /* Reject negative primitives to avoid unsigned wraparound (e.g. "-1"). */
        if (num_buf[0] == '-')
                return -1;

        errno = 0;
        val = strtoull(num_buf, &end, 10);
        /* Require a full decimal parse that fits exactly in size_t. */
        if (errno != 0 || end == num_buf || *end != '\0' || val > (unsigned long long) SIZE_MAX)
                return -1;

        *out = (size_t) val;
        return 0;
}

/**
 * @brief Compute decoded byte length of an optional hex-string JSON token.
 *
 * @param [in] token JSON string token containing hexadecimal data, or NULL
 * @param [out] out_len Decoded length in bytes
 *
 * @return Operation status.
 * @retval 0 Length computed successfully.
 * @retval -1 Token is not a valid even-length hex string.
 */
static int
json_hex_token_len_bytes(const json_tok *token, size_t *out_len)
{
        int str_len;

        if (token == NULL) {
                *out_len = 0;
                return 0;
        }

        if (token->type != JSON_TOK_STRING)
                return -1;

        str_len = token->end - token->start;
        /* Hex strings must have an even number of characters. */
        if (str_len < 0 || (str_len & 1) != 0)
                return -1;

        *out_len = (size_t) str_len / 2;
        return 0;
}

/**
 * @brief Convert a bit length to required byte length, rounded up.
 *
 * @param [in] bit_size Declared size in bits
 * @param [out] out_bytes Required size in bytes
 *
 * @return Operation status.
 * @retval 0 Conversion completed.
 * @retval -1 Overflow while converting bits to bytes.
 */
static int
json_bits_to_bytes_ceil(const size_t bit_size, size_t *out_bytes)
{
        /* Prevent overflow in "(bit_size + 7) / 8". */
        if (bit_size > SIZE_MAX - 7)
                return -1;

        *out_bytes = (bit_size + 7) / 8;
        return 0;
}

/**
 * @brief Validate that a decoded buffer can hold a declared bit-size payload.
 *
 * @param [in] bit_size Declared payload size in bits
 * @param [in] buf_len Available decoded buffer length in bytes
 *
 * @return Operation status.
 * @retval 0 Buffer is large enough for the declared size.
 * @retval -1 Declared size is invalid or exceeds available buffer length.
 */
static int
json_validate_declared_size(const size_t bit_size, const size_t buf_len)
{
        size_t required_len;

        if (json_bits_to_bytes_ceil(bit_size, &required_len) < 0)
                return -1;

        /* Declared bit length must fit in the decoded byte buffer. */
        if (buf_len < required_len)
                return -1;

        return 0;
}

/**
 * @brief Convert one hexadecimal character into its 4-bit value.
 *
 * @param [in] c Hexadecimal character
 *
 * @return Nibble value in range [0..15].
 * @retval -1 Invalid hexadecimal character.
 */
static int
json_hex_nibble(const char c)
{
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

/**
 * @brief Decode a hex string token into a binary buffer owned by ctx.
 *
 * @param [in] json JSON document text
 * @param [in] token Hex string token to decode (or NULL)
 * @param [in,out] ctx Allocation context owning decoded buffer
 * @param [out] out_buf Output pointer to decoded buffer
 *
 * @return Operation status.
 * @retval 0 Token decoded successfully.
 * @retval -1 Invalid token format or allocation failure.
 */
static int
json_decode_hex_token(const char *json, const json_tok *token, struct test_json_alloc_ctx *ctx,
                      const char **out_buf)
{
        const char *ptr;
        size_t byte_len = 0;
        unsigned char *buf;

        if (token == NULL) {
                *out_buf = NULL;
                return 0;
        }

        if (json_hex_token_len_bytes(token, &byte_len) < 0)
                return -1;
        buf = alloc_ctx_alloc(ctx, (byte_len == 0) ? 1 : byte_len);
        if (buf == NULL)
                return -1;

        ptr = json + token->start;
        for (size_t i = 0; i < byte_len; i++) {
                int hi = json_hex_nibble(ptr[(2 * i) + 0]);
                int lo = json_hex_nibble(ptr[(2 * i) + 1]);

                if (hi < 0 || lo < 0)
                        return -1;
                buf[i] = (unsigned char) ((hi << 4) | lo);
        }

        *out_buf = (const char *) buf;
        return 0;
}

/**
 * @brief Map JSON result strings ("valid" or "invalid") to integer flags.
 *
 * @param [in] json JSON document text
 * @param [in] token Result string token
 * @param [out] result_valid Parsed result flag
 *
 * @return Operation status.
 * @retval 0 Result token parsed successfully.
 * @retval -1 Invalid token format or unsupported value.
 */
static int
json_result_to_valid(const char *json, const json_tok *token, int *result_valid)
{
        if (token->type != JSON_TOK_STRING)
                return -1;

        if (json_token_eq(json, token, "valid")) {
                *result_valid = 1;
                return 0;
        }

        if (json_token_eq(json, token, "invalid")) {
                *result_valid = 0;
                return 0;
        }

        return -1;
}

/**
 * @brief Load and tokenize a JSON document from disk.
 *
 * @param [in] path JSON file path
 * @param [in,out] ctx Allocation context for owned buffers
 * @param [out] json_out Loaded JSON text buffer
 * @param [out] tokens_out Token array buffer
 * @param [out] token_cnt_out Number of parsed tokens
 *
 * @return Operation status.
 * @retval 0 JSON file loaded and tokenized successfully.
 * @retval -1 File I/O, parse, or allocation failure.
 */
static int
json_load_doc(const char *path, struct test_json_alloc_ctx *ctx, char **json_out,
              json_tok **tokens_out, int *token_cnt_out)
{
        FILE *fp = NULL;
        long file_len;
        size_t read_len;
        char *json = NULL;
        json_tok *tokens = NULL;
        size_t token_cap = 4096;
        int token_cnt;
        const char *err_stage = "json_load_doc";
        const char *err_reason = NULL;
        int errnum = 0;
        int parse_status_out = 0;

        fp = fopen(path, "rb");
        if (fp == NULL) {
                err_reason = "unable to open JSON file";
                errnum = errno;
                goto err;
        }

        if (fseek(fp, 0, SEEK_END) != 0) {
                err_reason = "unable to seek to end of JSON file";
                errnum = errno;
                goto err;
        }

        file_len = ftell(fp);
        if (file_len < 0) {
                err_reason = "unable to get JSON file size";
                errnum = errno;
                goto err;
        }

        if (fseek(fp, 0, SEEK_SET) != 0) {
                err_reason = "unable to seek to start of JSON file";
                errnum = errno;
                goto err;
        }

        json = alloc_ctx_alloc(ctx, (size_t) file_len + 1);
        if (json == NULL) {
                err_reason = "unable to allocate JSON document buffer";
                errnum = ENOMEM;
                goto err;
        }

        read_len = fread(json, 1, (size_t) file_len, fp);
        if (read_len != (size_t) file_len) {
                err_reason = "unable to read complete JSON file";
                errnum = ferror(fp) ? errno : 0;
                goto err;
        }

        json[file_len] = '\0';

        tokens = malloc(token_cap * sizeof(*tokens));
        if (tokens == NULL) {
                err_reason = "unable to allocate JSON token buffer";
                errnum = ENOMEM;
                goto err;
        }

        /* Grow token storage and retry tokenization when capacity is exhausted. */
        for (;;) {
                int parse_status;
                parse_status = json_tokenize_document(json, (size_t) file_len, tokens, token_cap);
                if (parse_status == JSON_PARSE_NOMEM) {
                        json_tok *new_tokens;

                        token_cap *= 2;
                        new_tokens = realloc(tokens, token_cap * sizeof(*tokens));
                        if (new_tokens == NULL) {
                                err_reason = "unable to grow JSON token buffer";
                                errnum = ENOMEM;
                                goto err;
                        }
                        tokens = new_tokens;
                        continue;
                }

                if (parse_status < 0) {
                        err_stage = "json_load_doc/tokenize";
                        err_reason = json_parse_err_to_reason(parse_status);
                        parse_status_out = parse_status;
                        goto err;
                }

                token_cnt = parse_status;
                break;
        }

        if (alloc_ctx_add_ptr(ctx, tokens) < 0) {
                err_reason = "unable to register JSON token buffer in allocation context";
                errnum = ENOMEM;
                goto err;
        }

        fclose(fp);

        *json_out = json;
        *tokens_out = tokens;
        *token_cnt_out = token_cnt;

        return 0;

err:
        if (fp != NULL)
                fclose(fp);
        free(tokens);
        json_report_parse_error(path, err_stage, err_reason, errnum, parse_status_out, -1, -1,
                                NULL);
        return -1;
}

/**
 * @brief Parse MAC vectors from a JSON file into a sentinel-terminated
 *        struct mac_test array.
 *
 * @param [in] path JSON file path
 * @param [out] out_vectors Parsed MAC vector array
 * @param [out] out_ctx Allocation context for json_free_test_ctx()
 *
 * @return Operation status.
 * @retval 0 Vectors parsed successfully.
 * @retval -1 Invalid input, parse failure, or allocation failure.
 */
int
json_load_mac_test(const char *path, struct mac_test **out_vectors,
                   struct test_json_alloc_ctx **out_ctx)
{
        struct test_json_alloc_ctx *ctx;
        char *json = NULL;
        json_tok *tokens = NULL;
        int token_cnt = 0;
        int test_groups_idx;
        int tg_pos;
        size_t test_cnt = 0;
        struct mac_test *vectors;
        size_t rec = 0;
        const char *err_reason = NULL;
        int errnum = 0;
        int tg_idx = -1;
        int test_idx = -1;
        size_t tcid = 0;
        int have_tcid = 0;

        if (path == NULL || out_vectors == NULL || out_ctx == NULL) {
                json_report_parse_error(path, "json_load_mac_test", "invalid function arguments", 0,
                                        0, -1, -1, NULL);
                return -1;
        }

        *out_vectors = NULL;
        *out_ctx = NULL;

        ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
                json_report_parse_error(path, "json_load_mac_test",
                                        "unable to allocate JSON allocation context", ENOMEM, 0, -1,
                                        -1, NULL);
                return -1;
        }

        if (json_load_doc(path, ctx, &json, &tokens, &token_cnt) < 0)
                goto err_no_report;

        if (token_cnt <= 0 || tokens[0].type != JSON_TOK_OBJECT) {
                set_parse_error(&err_reason, &errnum, "top-level JSON token must be an object", 0);
                goto err;
        }

        test_groups_idx = json_object_get(json, tokens, token_cnt, 0, "testGroups");
        if (test_groups_idx < 0 || tokens[test_groups_idx].type != JSON_TOK_ARRAY) {
                set_parse_error(&err_reason, &errnum,
                                "missing or invalid top-level testGroups array", 0);
                goto err;
        }

        /* First pass: count all tests to size the output vector array. */
        tg_pos = test_groups_idx + 1;
        for (int i = 0; i < tokens[test_groups_idx].size; i++) {
                int tests_idx;

                tg_idx = i;
                test_idx = -1;
                have_tcid = 0;
                tests_idx = json_object_get(json, tokens, token_cnt, tg_pos, "tests");
                if (tests_idx < 0 || tokens[tests_idx].type != JSON_TOK_ARRAY) {
                        set_parse_error(&err_reason, &errnum,
                                        "missing or invalid tests array in testGroup", 0);
                        goto err;
                }

                test_cnt += (size_t) tokens[tests_idx].size;
                tg_pos = json_token_skip(tokens, tg_pos);
        }

        vectors = alloc_ctx_alloc(ctx, (test_cnt + 1) * sizeof(*vectors));
        if (vectors == NULL) {
                set_parse_error(&err_reason, &errnum, "unable to allocate MAC vector array",
                                ENOMEM);
                goto err;
        }
        memset(vectors, 0, (test_cnt + 1) * sizeof(*vectors));

        /* Second pass: decode all test fields and payload buffers. */
        tg_pos = test_groups_idx + 1;
        for (int i = 0; i < tokens[test_groups_idx].size; i++) {
                int tc_pos;

                tg_idx = i;
                test_idx = -1;
                have_tcid = 0;
                const int tests_idx = json_object_get(json, tokens, token_cnt, tg_pos, "tests");
                if (tests_idx < 0 || tokens[tests_idx].type != JSON_TOK_ARRAY) {
                        set_parse_error(&err_reason, &errnum,
                                        "missing or invalid tests array in testGroup", 0);
                        goto err;
                }
                tc_pos = tests_idx + 1;
                for (int j = 0; j < tokens[tests_idx].size; j++) {
                        const int key_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                      tc_pos, tg_pos, "key");
                        const int msg_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                      tc_pos, tg_pos, "msg");
                        const int tag_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                      tc_pos, tg_pos, "tag");
                        const int iv_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                     tc_pos, tg_pos, "iv");
                        const int key_size_idx = json_member_with_fallback(
                                json, tokens, token_cnt, tc_pos, tg_pos, "keySize");
                        const int tag_size_idx = json_member_with_fallback(
                                json, tokens, token_cnt, tc_pos, tg_pos, "tagSize");
                        const int msg_size_idx = json_member_with_fallback(
                                json, tokens, token_cnt, tc_pos, tg_pos, "msgSize");
                        const int iv_size_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                          tc_pos, tg_pos, "ivSize");
                        const int tcid_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                       tc_pos, tg_pos, "tcId");
                        const int result_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                         tc_pos, tg_pos, "result");
                        size_t key_len = 0;
                        size_t msg_len = 0;
                        size_t tag_len = 0;
                        size_t iv_len = 0;

                        test_idx = j;
                        have_tcid = 0;
                        vectors[rec].keySize = 0;
                        vectors[rec].tagSize = 0;
                        vectors[rec].msgSize = 0;
                        vectors[rec].ivSize = 0;
                        vectors[rec].tcId = 0;

                        if (key_idx < 0) {
                                set_parse_error(&err_reason, &errnum, "missing key field", 0);
                                goto err;
                        }
                        if (msg_idx < 0) {
                                set_parse_error(&err_reason, &errnum, "missing msg field", 0);
                                goto err;
                        }
                        if (tag_idx < 0) {
                                set_parse_error(&err_reason, &errnum, "missing tag field", 0);
                                goto err;
                        }

                        if (key_size_idx >= 0) {
                                if (json_parse_size_t(json, &tokens[key_size_idx],
                                                      &vectors[rec].keySize) < 0) {
                                        set_parse_error(&err_reason, &errnum,
                                                        "invalid keySize value", 0);
                                        goto err;
                                }
                                /* hex chars * 4 bits/char = keySize in bits */
                                size_t derived =
                                        (size_t) (tokens[key_idx].end - tokens[key_idx].start) * 4;
                                if (derived != vectors[rec].keySize) {
                                        set_parse_error(&err_reason, &errnum,
                                                        "keySize does not match key length", 0);
                                        goto err;
                                }
                        } else
                                /* hex chars * 4 bits/char = keySize in bits */
                                vectors[rec].keySize =
                                        (size_t) (tokens[key_idx].end - tokens[key_idx].start) * 4;
                        if (tag_size_idx >= 0) {
                                if (json_parse_size_t(json, &tokens[tag_size_idx],
                                                      &vectors[rec].tagSize) < 0) {
                                        set_parse_error(&err_reason, &errnum,
                                                        "invalid tagSize value", 0);
                                        goto err;
                                }
                        } else
                                /* hex chars * 4 bits/char = tagSize in bits */
                                vectors[rec].tagSize =
                                        (size_t) (tokens[tag_idx].end - tokens[tag_idx].start) * 4;
                        if (msg_size_idx >= 0) {
                                if (json_parse_size_t(json, &tokens[msg_size_idx],
                                                      &vectors[rec].msgSize) < 0) {
                                        set_parse_error(&err_reason, &errnum,
                                                        "invalid msgSize value", 0);
                                        goto err;
                                }
                        } else {
                                /* hex chars * 4 bits/char = msgSize in bits */
                                vectors[rec].msgSize =
                                        (size_t) (tokens[msg_idx].end - tokens[msg_idx].start) * 4;
                        }
                        if (iv_size_idx >= 0) {
                                if (json_parse_size_t(json, &tokens[iv_size_idx],
                                                      &vectors[rec].ivSize) < 0) {
                                        set_parse_error(&err_reason, &errnum,
                                                        "invalid ivSize value", 0);
                                        goto err;
                                }
                                if (iv_idx >= 0) {
                                        /* hex chars * 4 bits/char = ivSize in bits */
                                        size_t derived = (size_t) (tokens[iv_idx].end -
                                                                   tokens[iv_idx].start) *
                                                         4;
                                        if (derived != vectors[rec].ivSize) {
                                                set_parse_error(&err_reason, &errnum,
                                                                "ivSize does not match iv length",
                                                                0);
                                                goto err;
                                        }
                                }
                        } else if (iv_idx >= 0)
                                /* hex chars * 4 bits/char = ivSize in bits */
                                vectors[rec].ivSize =
                                        (size_t) (tokens[iv_idx].end - tokens[iv_idx].start) * 4;
                        if (tcid_idx >= 0) {
                                if (json_parse_size_t(json, &tokens[tcid_idx], &vectors[rec].tcId) <
                                    0) {
                                        set_parse_error(&err_reason, &errnum, "invalid tcId value",
                                                        0);
                                        goto err;
                                }
                                tcid = vectors[rec].tcId;
                                have_tcid = 1;
                        }

                        if (json_hex_token_len_bytes(&tokens[key_idx], &key_len) < 0) {
                                set_parse_error(&err_reason, &errnum, "invalid key hex string", 0);
                                goto err;
                        }
                        if (json_hex_token_len_bytes(&tokens[msg_idx], &msg_len) < 0) {
                                set_parse_error(&err_reason, &errnum, "invalid msg hex string", 0);
                                goto err;
                        }
                        if (json_hex_token_len_bytes(&tokens[tag_idx], &tag_len) < 0) {
                                set_parse_error(&err_reason, &errnum, "invalid tag hex string", 0);
                                goto err;
                        }
                        if (json_hex_token_len_bytes((iv_idx >= 0) ? &tokens[iv_idx] : NULL,
                                                     &iv_len) < 0) {
                                set_parse_error(&err_reason, &errnum, "invalid iv hex string", 0);
                                goto err;
                        }

                        if (json_decode_hex_token(json, &tokens[key_idx], ctx, &vectors[rec].key) <
                            0) {
                                set_parse_error(&err_reason, &errnum,
                                                "unable to decode key hex string", 0);
                                goto err;
                        }
                        if (json_decode_hex_token(json, &tokens[msg_idx], ctx, &vectors[rec].msg) <
                            0) {
                                set_parse_error(&err_reason, &errnum,
                                                "unable to decode msg hex string", 0);
                                goto err;
                        }
                        if (json_decode_hex_token(json, &tokens[tag_idx], ctx, &vectors[rec].tag) <
                            0) {
                                set_parse_error(&err_reason, &errnum,
                                                "unable to decode tag hex string", 0);
                                goto err;
                        }
                        if (json_decode_hex_token(json, (iv_idx >= 0) ? &tokens[iv_idx] : NULL, ctx,
                                                  &vectors[rec].iv) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "unable to decode iv hex string", 0);
                                goto err;
                        }

                        if (json_validate_declared_size(vectors[rec].keySize, key_len) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "declared keySize exceeds decoded key length", 0);
                                goto err;
                        }
                        if (json_validate_declared_size(vectors[rec].msgSize, msg_len) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "declared msgSize exceeds decoded msg length", 0);
                                goto err;
                        }
                        if (json_validate_declared_size(vectors[rec].tagSize, tag_len) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "declared tagSize exceeds decoded tag length", 0);
                                goto err;
                        }
                        if (json_validate_declared_size(vectors[rec].ivSize, iv_len) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "declared ivSize exceeds decoded iv length", 0);
                                goto err;
                        }

                        if (result_idx < 0 || json_result_to_valid(json, &tokens[result_idx],
                                                                   &vectors[rec].resultValid) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "missing or invalid result field", 0);
                                goto err;
                        }

                        rec++;
                        tc_pos = json_token_skip(tokens, tc_pos);
                }

                tg_pos = json_token_skip(tokens, tg_pos);
        }

        *out_vectors = vectors;
        *out_ctx = ctx;

        return 0;

err:
        json_report_parse_error(path, "json_load_mac_test", err_reason, errnum, 0, tg_idx, test_idx,
                                have_tcid ? &tcid : NULL);
err_no_report:
        json_free_test_ctx(ctx);
        return -1;
}

/**
 * @brief Parse cipher vectors from a JSON file into a sentinel-terminated
 *        struct cipher_test array.
 *
 * @param [in] path JSON file path
 * @param [out] out_vectors Parsed cipher vector array
 * @param [out] out_ctx Allocation context for json_free_test_ctx()
 *
 * @return Operation status.
 * @retval 0 Vectors parsed successfully.
 * @retval -1 Invalid input, parse failure, or allocation failure.
 */
int
json_load_cipher_test(const char *path, struct cipher_test **out_vectors,
                      struct test_json_alloc_ctx **out_ctx)
{
        struct test_json_alloc_ctx *ctx;
        char *json = NULL;
        json_tok *tokens = NULL;
        int token_cnt = 0;
        int test_groups_idx;
        int tg_pos;
        size_t test_cnt = 0;
        struct cipher_test *vectors;
        size_t rec = 0;
        const char *err_reason = NULL;
        int errnum = 0;
        int tg_idx = -1;
        int test_idx = -1;
        size_t tcid = 0;
        int have_tcid = 0;

        if (path == NULL || out_vectors == NULL || out_ctx == NULL) {
                json_report_parse_error(path, "json_load_cipher_test", "invalid function arguments",
                                        0, 0, -1, -1, NULL);
                return -1;
        }

        *out_vectors = NULL;
        *out_ctx = NULL;

        ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
                json_report_parse_error(path, "json_load_cipher_test",
                                        "unable to allocate JSON allocation context", ENOMEM, 0, -1,
                                        -1, NULL);
                return -1;
        }

        if (json_load_doc(path, ctx, &json, &tokens, &token_cnt) < 0)
                goto err_no_report;

        if (token_cnt <= 0 || tokens[0].type != JSON_TOK_OBJECT) {
                set_parse_error(&err_reason, &errnum, "top-level JSON token must be an object", 0);
                goto err;
        }

        test_groups_idx = json_object_get(json, tokens, token_cnt, 0, "testGroups");
        if (test_groups_idx < 0 || tokens[test_groups_idx].type != JSON_TOK_ARRAY) {
                set_parse_error(&err_reason, &errnum,
                                "missing or invalid top-level testGroups array", 0);
                goto err;
        }

        /* First pass: count all tests to size the output vector array. */
        tg_pos = test_groups_idx + 1;
        for (int i = 0; i < tokens[test_groups_idx].size; i++) {
                const int tests_idx = json_object_get(json, tokens, token_cnt, tg_pos, "tests");

                tg_idx = i;
                test_idx = -1;
                have_tcid = 0;
                if (tests_idx < 0 || tokens[tests_idx].type != JSON_TOK_ARRAY) {
                        set_parse_error(&err_reason, &errnum,
                                        "missing or invalid tests array in testGroup", 0);
                        goto err;
                }

                test_cnt += (size_t) tokens[tests_idx].size;
                tg_pos = json_token_skip(tokens, tg_pos);
        }

        vectors = alloc_ctx_alloc(ctx, (test_cnt + 1) * sizeof(*vectors));
        if (vectors == NULL) {
                set_parse_error(&err_reason, &errnum, "unable to allocate cipher vector array",
                                ENOMEM);
                goto err;
        }
        memset(vectors, 0, (test_cnt + 1) * sizeof(*vectors));

        /* Second pass: decode all test fields and payload buffers. */
        tg_pos = test_groups_idx + 1;
        for (int i = 0; i < tokens[test_groups_idx].size; i++) {
                const int tests_idx = json_object_get(json, tokens, token_cnt, tg_pos, "tests");
                int tc_pos;

                tg_idx = i;
                test_idx = -1;
                have_tcid = 0;
                if (tests_idx < 0 || tokens[tests_idx].type != JSON_TOK_ARRAY) {
                        set_parse_error(&err_reason, &errnum,
                                        "missing or invalid tests array in testGroup", 0);
                        goto err;
                }
                tc_pos = tests_idx + 1;

                for (int j = 0; j < tokens[tests_idx].size; j++) {
                        const int key_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                      tc_pos, tg_pos, "key");
                        const int iv_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                     tc_pos, tg_pos, "iv");
                        const int msg_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                      tc_pos, tg_pos, "msg");
                        const int ct_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                     tc_pos, tg_pos, "ct");
                        const int key_size_idx = json_member_with_fallback(
                                json, tokens, token_cnt, tc_pos, tg_pos, "keySize");
                        const int iv_size_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                          tc_pos, tg_pos, "ivSize");
                        const int msg_size_idx = json_member_with_fallback(
                                json, tokens, token_cnt, tc_pos, tg_pos, "msgSize");
                        const int tcid_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                       tc_pos, tg_pos, "tcId");
                        const int result_idx = json_member_with_fallback(json, tokens, token_cnt,
                                                                         tc_pos, tg_pos, "result");
                        size_t key_len = 0;
                        size_t iv_len = 0;
                        size_t msg_len = 0;
                        size_t ct_len = 0;

                        test_idx = j;
                        have_tcid = 0;
                        vectors[rec].keySize = 0;
                        vectors[rec].ivSize = 0;
                        vectors[rec].msgSize = 0;
                        vectors[rec].tcId = 0;

                        if (key_idx < 0) {
                                set_parse_error(&err_reason, &errnum, "missing key field", 0);
                                goto err;
                        }
                        if (iv_idx < 0) {
                                set_parse_error(&err_reason, &errnum, "missing iv field", 0);
                                goto err;
                        }
                        if (msg_idx < 0) {
                                set_parse_error(&err_reason, &errnum, "missing msg field", 0);
                                goto err;
                        }
                        if (ct_idx < 0) {
                                set_parse_error(&err_reason, &errnum, "missing ct field", 0);
                                goto err;
                        }

                        if (key_size_idx >= 0) {
                                if (json_parse_size_t(json, &tokens[key_size_idx],
                                                      &vectors[rec].keySize) < 0) {
                                        set_parse_error(&err_reason, &errnum,
                                                        "invalid keySize value", 0);
                                        goto err;
                                }
                                /* hex chars * 4 bits/char = keySize in bits */
                                size_t derived =
                                        (size_t) (tokens[key_idx].end - tokens[key_idx].start) * 4;
                                if (derived != vectors[rec].keySize) {
                                        set_parse_error(&err_reason, &errnum,
                                                        "keySize does not match key length", 0);
                                        goto err;
                                }
                        } else
                                /* hex chars * 4 bits/char = keySize in bits */
                                vectors[rec].keySize =
                                        (size_t) (tokens[key_idx].end - tokens[key_idx].start) * 4;

                        if (iv_size_idx >= 0) {
                                if (json_parse_size_t(json, &tokens[iv_size_idx],
                                                      &vectors[rec].ivSize) < 0) {
                                        set_parse_error(&err_reason, &errnum,
                                                        "invalid ivSize value", 0);
                                        goto err;
                                }
                                /* hex chars * 4 bits/char = ivSize in bits */
                                size_t derived =
                                        (size_t) (tokens[iv_idx].end - tokens[iv_idx].start) * 4;
                                if (derived != vectors[rec].ivSize) {
                                        set_parse_error(&err_reason, &errnum,
                                                        "ivSize does not match iv length", 0);
                                        goto err;
                                }
                        } else
                                /* hex chars * 4 bits/char = ivSize in bits */
                                vectors[rec].ivSize =
                                        (size_t) (tokens[iv_idx].end - tokens[iv_idx].start) * 4;

                        if (msg_size_idx >= 0) {
                                if (json_parse_size_t(json, &tokens[msg_size_idx],
                                                      &vectors[rec].msgSize) < 0) {
                                        set_parse_error(&err_reason, &errnum,
                                                        "invalid msgSize value", 0);
                                        goto err;
                                }
                        } else {
                                /* hex chars * 4 bits/char = msgSize in bits */
                                vectors[rec].msgSize =
                                        (size_t) (tokens[msg_idx].end - tokens[msg_idx].start) * 4;
                        }

                        if (tcid_idx >= 0) {
                                if (json_parse_size_t(json, &tokens[tcid_idx], &vectors[rec].tcId) <
                                    0) {
                                        set_parse_error(&err_reason, &errnum, "invalid tcId value",
                                                        0);
                                        goto err;
                                }
                                tcid = vectors[rec].tcId;
                                have_tcid = 1;
                        }

                        if (json_hex_token_len_bytes(&tokens[key_idx], &key_len) < 0) {
                                set_parse_error(&err_reason, &errnum, "invalid key hex string", 0);
                                goto err;
                        }
                        if (json_hex_token_len_bytes(&tokens[iv_idx], &iv_len) < 0) {
                                set_parse_error(&err_reason, &errnum, "invalid iv hex string", 0);
                                goto err;
                        }
                        if (json_hex_token_len_bytes(&tokens[msg_idx], &msg_len) < 0) {
                                set_parse_error(&err_reason, &errnum, "invalid msg hex string", 0);
                                goto err;
                        }
                        if (json_hex_token_len_bytes(&tokens[ct_idx], &ct_len) < 0) {
                                set_parse_error(&err_reason, &errnum, "invalid ct hex string", 0);
                                goto err;
                        }

                        if (json_decode_hex_token(json, &tokens[key_idx], ctx, &vectors[rec].key) <
                            0) {
                                set_parse_error(&err_reason, &errnum,
                                                "unable to decode key hex string", 0);
                                goto err;
                        }
                        if (json_decode_hex_token(json, &tokens[iv_idx], ctx, &vectors[rec].iv) <
                            0) {
                                set_parse_error(&err_reason, &errnum,
                                                "unable to decode iv hex string", 0);
                                goto err;
                        }
                        if (json_decode_hex_token(json, &tokens[msg_idx], ctx, &vectors[rec].msg) <
                            0) {
                                set_parse_error(&err_reason, &errnum,
                                                "unable to decode msg hex string", 0);
                                goto err;
                        }
                        if (json_decode_hex_token(json, &tokens[ct_idx], ctx, &vectors[rec].ct) <
                            0) {
                                set_parse_error(&err_reason, &errnum,
                                                "unable to decode ct hex string", 0);
                                goto err;
                        }

                        if (json_validate_declared_size(vectors[rec].keySize, key_len) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "declared keySize exceeds decoded key length", 0);
                                goto err;
                        }
                        if (json_validate_declared_size(vectors[rec].ivSize, iv_len) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "declared ivSize exceeds decoded iv length", 0);
                                goto err;
                        }
                        if (json_validate_declared_size(vectors[rec].msgSize, msg_len) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "declared msgSize exceeds decoded msg length", 0);
                                goto err;
                        }
                        if (json_validate_declared_size(vectors[rec].msgSize, ct_len) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "declared msgSize exceeds decoded ct length", 0);
                                goto err;
                        }

                        if (result_idx < 0 || json_result_to_valid(json, &tokens[result_idx],
                                                                   &vectors[rec].resultValid) < 0) {
                                set_parse_error(&err_reason, &errnum,
                                                "missing or invalid result field", 0);
                                goto err;
                        }

                        rec++;
                        tc_pos = json_token_skip(tokens, tc_pos);
                }

                tg_pos = json_token_skip(tokens, tg_pos);
        }

        *out_vectors = vectors;
        *out_ctx = ctx;

        return 0;

err:
        json_report_parse_error(path, "json_load_cipher_test", err_reason, errnum, 0, tg_idx,
                                test_idx, have_tcid ? &tcid : NULL);
err_no_report:
        json_free_test_ctx(ctx);
        return -1;
}

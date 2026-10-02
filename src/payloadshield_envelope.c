#include "payloadshield_envelope.h"

#include <stdint.h>
#include <string.h>

#include <openssl/crypto.h>

static void
payloadshield_envelope_skip_space(const unsigned char **cursor,
    const unsigned char *end)
{
    while (*cursor < end && (**cursor == ' ' || **cursor == '\t'
           || **cursor == '\r' || **cursor == '\n'))
    {
        (*cursor)++;
    }
}

int
payloadshield_envelope_unwrap(const unsigned char *json, size_t json_len,
    payloadshield_buffer_t *encoded_payload)
{
    static const unsigned char name[] = "\"encrypted\"";
    const unsigned char *cursor = json;
    const unsigned char *end;
    const unsigned char *value_start;
    const unsigned char *value_end;
    size_t normalized_len = 0;
    unsigned char *copy;

    if (encoded_payload == NULL || json == NULL) {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    encoded_payload->data = NULL;
    encoded_payload->len = 0;
    end = json + json_len;
    payloadshield_envelope_skip_space(&cursor, end);
    if (cursor == end || *cursor++ != '{')
    {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    payloadshield_envelope_skip_space(&cursor, end);
    if ((size_t) (end - cursor) < sizeof(name) - 1
        || memcmp(cursor, name, sizeof(name) - 1) != 0)
    {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    cursor += sizeof(name) - 1;
    payloadshield_envelope_skip_space(&cursor, end);
    if (cursor == end || *cursor++ != ':') {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    payloadshield_envelope_skip_space(&cursor, end);
    if (cursor == end || *cursor++ != '"') {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    value_start = cursor;
    while (cursor < end && *cursor != '"') {
        unsigned char c = *cursor++;
        if (c == '\\') {
            if (cursor == end || *cursor++ != '/') {
                return PAYLOADSHIELD_CRYPTO_INVALID;
            }
            normalized_len++;
            continue;
        }
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
        {
            return PAYLOADSHIELD_CRYPTO_INVALID;
        }
        normalized_len++;
    }
    if (cursor == end) {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    value_end = cursor;
    cursor++;
    payloadshield_envelope_skip_space(&cursor, end);
    if (cursor == end || *cursor++ != '}') {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    payloadshield_envelope_skip_space(&cursor, end);
    if (cursor != end || normalized_len == 0) {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }

    copy = OPENSSL_malloc(normalized_len);
    if (copy == NULL) {
        return PAYLOADSHIELD_CRYPTO_NOMEM;
    }
    {
        const unsigned char *source = value_start;
        size_t index = 0;
        while (source < value_end) {
            if (*source == '\\') source++;
            copy[index++] = *source++;
        }
    }
    encoded_payload->data = copy;
    encoded_payload->len = normalized_len;
    return PAYLOADSHIELD_CRYPTO_OK;
}

int
payloadshield_envelope_wrap(const unsigned char *encoded_payload,
    size_t encoded_payload_len, payloadshield_buffer_t *json)
{
    static const unsigned char prefix[] = "{\"encrypted\":\"";
    static const unsigned char suffix[] = "\"}";
    unsigned char *result;
    size_t i;
    size_t total;

    if (json == NULL || (encoded_payload == NULL && encoded_payload_len != 0)
        || encoded_payload_len > SIZE_MAX - sizeof(prefix) - sizeof(suffix))
    {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    json->data = NULL;
    json->len = 0;
    for (i = 0; i < encoded_payload_len; i++) {
        unsigned char c = encoded_payload[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
        {
            return PAYLOADSHIELD_CRYPTO_INVALID;
        }
    }

    total = sizeof(prefix) - 1 + encoded_payload_len + sizeof(suffix) - 1;
    result = OPENSSL_malloc(total);
    if (result == NULL) {
        return PAYLOADSHIELD_CRYPTO_NOMEM;
    }
    memcpy(result, prefix, sizeof(prefix) - 1);
    if (encoded_payload_len != 0) {
        memcpy(result + sizeof(prefix) - 1, encoded_payload, encoded_payload_len);
    }
    memcpy(result + sizeof(prefix) - 1 + encoded_payload_len,
           suffix, sizeof(suffix) - 1);
    json->data = result;
    json->len = total;
    return PAYLOADSHIELD_CRYPTO_OK;
}
#include "jwtc.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <time.h>

static char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *copy = malloc(len);
    if (copy) strcpy(copy, s);
    return copy;
}

static void set_error(char **error, const char *msg) {
    if (error) {
        *error = xstrdup(msg);
    }
}

static char *base64url_encode(const unsigned char *input, size_t len, char **error) {
    if (!input || len == 0) {
        char *empty = malloc(1);
        if (!empty) {
            set_error(error, "Memory allocation failed");
            return NULL;
        }
        *empty = '\0';
        return empty;
    }

    size_t out_len = EVP_ENCODE_LENGTH(len);
    char *encoded = malloc(out_len + 1);
    if (!encoded) {
        set_error(error, "Memory allocation failed");
        return NULL;
    }

    EVP_EncodeBlock((unsigned char *)encoded, input, len);

    for (size_t i = 0; i < out_len; i++) {
        if (encoded[i] == '+') encoded[i] = '-';
        else if (encoded[i] == '/') encoded[i] = '_';
        else if (encoded[i] == '=') {
            encoded[i] = '\0';  
            break;
        }
    }

    return encoded;
}

static unsigned char *base64url_decode(const char *input, size_t *out_len, char **error) {
    if (!input || !*input) {
        *out_len = 0;
        return malloc(1);  
    }

    char *tmp = xstrdup(input);
    if (!tmp) {
        set_error(error, "Memory allocation failed");
        return NULL;
    }

    for (size_t i = 0; tmp[i]; i++) {
        if (tmp[i] == '-') tmp[i] = '+';
        if (tmp[i] == '_') tmp[i] = '/';
    }

    size_t len = strlen(tmp);
    size_t padding = (4 - (len % 4)) % 4;
    char *padded = realloc(tmp, len + padding + 1);  
    if (!padded) {
        free(tmp);
        set_error(error, "Memory allocation failed");
        return NULL;
    }
    tmp = padded;  
    memset(tmp + len, '=', padding);
    tmp[len + padding] = '\0';

    size_t max_out = (len + padding) * 3 / 4 + 1;  
    unsigned char *decoded = malloc(max_out);
    if (!decoded) {
        free(tmp);
        set_error(error, "Memory allocation failed");
        return NULL;
    }

    int decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)tmp, len + padding);
    if (decoded_len < 0) {
        free(decoded);
        free(tmp);
        set_error(error, "Invalid base64 input");
        return NULL;
    }

    *out_len = decoded_len;
    free(tmp);
    return decoded;
}

char *jwtc_generate(const char *secret, int expiry_seconds, json_object *claims, char **error) {
    if (!secret || !claims) {
        set_error(error, "Invalid secret or claims");
        return NULL;
    }

    json_object *header = json_object_new_object();
    if (!header) {
        set_error(error, "Failed to create header JSON");
        return NULL;
    }
    json_object_object_add(header, "alg", json_object_new_string("HS256"));
    json_object_object_add(header, "typ", json_object_new_string("JWT"));
    const char *header_json = json_object_to_json_string(header);
    char *header_b64 = base64url_encode((unsigned char *)header_json, strlen(header_json), error);
    json_object_put(header);
    if (!header_b64) return NULL;

    json_object *payload = json_object_new_object();
    if (!payload) {
        free(header_b64);
        set_error(error, "Failed to create payload JSON");
        return NULL;
    }
    json_object_object_foreach(claims, key, val) {
        json_object_object_add(payload, key, json_object_get(val));
    }
    json_object_object_add(payload, "iat", json_object_new_int64(time(NULL)));
    json_object_object_add(payload, "exp", json_object_new_int64(time(NULL) + expiry_seconds));
    const char *payload_json = json_object_to_json_string(payload);
    char *payload_b64 = base64url_encode((unsigned char *)payload_json, strlen(payload_json), error);
    json_object_put(payload);
    if (!payload_b64) {
        free(header_b64);
        return NULL;
    }

    size_t input_len = strlen(header_b64) + 1 + strlen(payload_b64);
    char *input = malloc(input_len + 1);
    if (!input) {
        free(header_b64);
        free(payload_b64);
        set_error(error, "Memory allocation failed");
        return NULL;
    }
    snprintf(input, input_len + 1, "%s.%s", header_b64, payload_b64);

    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    if (!HMAC(EVP_sha256(), (const unsigned char *)secret, strlen(secret), (unsigned char *)input, input_len, hmac, &hmac_len)) {
        free(header_b64);
        free(payload_b64);
        free(input);
        set_error(error, "HMAC computation failed");
        return NULL;
    }
    char *signature_b64 = base64url_encode(hmac, hmac_len, error);
    if (!signature_b64) {
        free(header_b64);
        free(payload_b64);
        free(input);
        return NULL;
    }

    size_t token_len = input_len + 1 + strlen(signature_b64);
    char *token = malloc(token_len + 1);
    if (!token) {
        free(header_b64);
        free(payload_b64);
        free(input);
        free(signature_b64);
        set_error(error, "Memory allocation failed");
        return NULL;
    }
    snprintf(token, token_len + 1, "%s.%s.%s", header_b64, payload_b64, signature_b64);

    free(header_b64);
    free(payload_b64);
    free(input);
    free(signature_b64);
    return token;
}

bool jwtc_validate(const char *token, const char *secret, int time_offset_seconds, json_object **claims, char **error) {
    if (!token || !secret || !claims) {
        set_error(error, "Invalid token, secret, or claims pointer");
        return false;
    }

    char *header_b64 = xstrdup(token);
    if (!header_b64) {
        set_error(error, "Memory allocation failed");
        return false;
    }
    char *payload_b64 = strchr(header_b64, '.');
    if (!payload_b64) {
        free(header_b64);
        set_error(error, "Invalid JWT format: missing payload");
        return false;
    }
    *payload_b64++ = '\0';
    char *signature_b64 = strchr(payload_b64, '.');
    if (!signature_b64) {
        free(header_b64);
        set_error(error, "Invalid JWT format: missing signature");
        return false;
    }
    *signature_b64++ = '\0';

    size_t header_len;
    unsigned char *header_json = base64url_decode(header_b64, &header_len, error);
    if (!header_json) {
        free(header_b64);
        return false;
    }
    json_object *header = json_tokener_parse((char *)header_json);
    free(header_json);
    if (!header) {
        free(header_b64);
        set_error(error, "Failed to parse header JSON");
        return false;
    }
    json_object *alg_obj;
    if (!json_object_object_get_ex(header, "alg", &alg_obj) ||
        strcmp(json_object_get_string(alg_obj), "HS256") != 0) {
        json_object_put(header);
        free(header_b64);
        set_error(error, "Invalid or missing alg claim");
        return false;
    }
    json_object_put(header);

    size_t input_len = strlen(header_b64) + 1 + strlen(payload_b64);
    char *input = malloc(input_len + 1);
    if (!input) {
        free(header_b64);
        set_error(error, "Memory allocation failed");
        return false;
    }
    snprintf(input, input_len + 1, "%s.%s", header_b64, payload_b64);
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    if (!HMAC(EVP_sha256(), (const unsigned char *)secret, strlen(secret), (unsigned char *)input, input_len, hmac, &hmac_len)) {
        free(header_b64);
        free(input);
        set_error(error, "HMAC computation failed");
        return false;
    }
    char *expected_signature_b64 = base64url_encode(hmac, hmac_len, error);
    if (!expected_signature_b64 || strcmp(signature_b64, expected_signature_b64) != 0) {
        free(header_b64);
        free(input);
        free(expected_signature_b64);
        set_error(error, "Signature verification failed");
        return false;
    }
    free(expected_signature_b64);

    size_t payload_len;
    unsigned char *payload_json = base64url_decode(payload_b64, &payload_len, error);
    if (!payload_json) {
        free(header_b64);
        free(input);
        return false;
    }
    *claims = json_tokener_parse((char *)payload_json);
    free(payload_json);
    if (!*claims) {
        free(header_b64);
        free(input);
        set_error(error, "Failed to parse payload JSON");
        return false;
    }

    json_object *exp_obj;
    if (!json_object_object_get_ex(*claims, "exp", &exp_obj) ||
        !json_object_is_type(exp_obj, json_type_int)) {
        json_object_put(*claims);
        *claims = NULL;
        free(header_b64);
        free(input);
        set_error(error, "Missing or invalid exp claim");
        return false;
    }
    long exp = json_object_get_int64(exp_obj);
    if (exp <= time(NULL) + time_offset_seconds) {
        json_object_put(*claims);
        *claims = NULL;
        free(header_b64);
        free(input);
        set_error(error, "Token expired");
        return false;
    }

    free(header_b64);
    free(input);
    return true;
}

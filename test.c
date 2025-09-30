#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jwtc.h"

static int test_generate_and_validate(void) {
        printf("Test: Generate and validate valid JWT\n");
        const char* secret       = "simple-secret-key-1234567890abcdef";
        const char* expected_sub = "test-user";
        json_object* claims      = json_object_new_object();
        if (!claims) {
                printf("FAIL: Failed to create claims object\n");
                return 1;
        }
        json_object_object_add(claims, "sub",
                               json_object_new_string(expected_sub));
        json_object_object_add(claims, "user_id", json_object_new_int(123));

        char* error = NULL;
        char* token = jwtc_generate(secret, 3600, claims, &error);
        json_object_put(claims);
        if (!token) {
                printf("FAIL: Generation error: %s\n",
                       error ? error : "Unknown");
                free(error);
                return 1;
        }

        json_object* validated_claims = NULL;
        error                         = NULL;
        bool valid = jwtc_validate(token, secret, 0, &validated_claims, &error);
        if (!valid) {
                printf("FAIL: Validation error: %s\n",
                       error ? error : "Unknown");
                free(error);
                free(token);
                return 1;
        }

        json_object* sub_obj;
        if (!json_object_object_get_ex(validated_claims, "sub", &sub_obj) ||
            !json_object_is_type(sub_obj, json_type_string) ||
            strcmp(json_object_get_string(sub_obj), expected_sub) != 0) {
                printf("FAIL: Sub claim mismatch\n");
                json_object_put(validated_claims);
                free(token);
                return 1;
        }

        json_object *iat_obj, *exp_obj;
        if (!json_object_object_get_ex(validated_claims, "iat", &iat_obj) ||
            !json_object_is_type(iat_obj, json_type_int) ||
            !json_object_object_get_ex(validated_claims, "exp", &exp_obj) ||
            !json_object_is_type(exp_obj, json_type_int)) {
                printf("FAIL: Missing or invalid iat/exp claims\n");
                json_object_put(validated_claims);
                free(token);
                return 1;
        }
        long iat = json_object_get_int64(iat_obj);
        long exp = json_object_get_int64(exp_obj);
        if (exp <= iat || exp > iat + 3700) {
                printf("FAIL: Invalid iat/exp values\n");
                json_object_put(validated_claims);
                free(token);
                return 1;
        }

        json_object_put(validated_claims);
        free(token);
        free(error);
        printf("PASS\n");
        return 0;
}

static int test_invalid_secret(void) {
        printf("Test: Validate with wrong secret\n");
        const char* secret       = "simple-secret-key-1234567890abcdef";
        const char* wrong_secret = "wrong-secret";
        json_object* claims      = json_object_new_object();
        json_object_object_add(claims, "sub",
                               json_object_new_string("test-user"));

        char* error = NULL;
        char* token = jwtc_generate(secret, 3600, claims, &error);
        json_object_put(claims);
        if (!token) {
                free(error);
                return 1;
        }

        json_object* validated_claims = NULL;
        error                         = NULL;
        bool valid =
            jwtc_validate(token, wrong_secret, 0, &validated_claims, &error);
        free(token);
        free(error);
        json_object_put(validated_claims);

        if (valid) {
                printf(
                    "FAIL: Validation should have failed with wrong secret\n");
                return 1;
        }
        printf("PASS (expected failure)\n");
        return 0;
}

static int test_expired_token(void) {
        printf("Test: Validate expired token\n");
        const char* secret  = "simple-secret-key-1234567890abcdef";
        json_object* claims = json_object_new_object();
        json_object_object_add(claims, "sub",
                               json_object_new_string("test-user"));
        json_object_object_add(claims, "exp", json_object_new_int(1));

        char* error = NULL;
        char* token = jwtc_generate(secret, -100, claims, &error);
        json_object_put(claims);
        if (!token) {
                free(error);
                return 1;
        }

        json_object* validated_claims = NULL;
        error                         = NULL;
        bool valid = jwtc_validate(token, secret, 0, &validated_claims, &error);
        free(token);
        free(error);
        json_object_put(validated_claims);

        if (valid) {
                printf("FAIL: Expired token should fail validation\n");
                return 1;
        }
        printf("PASS (expected failure)\n");
        return 0;
}

static int test_invalid_format(void) {
        printf("Test: Validate malformed token\n");
        const char* secret = "simple-secret-key-1234567890abcdef";
        const char* invalid_token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.malformed";

        json_object* validated_claims = NULL;
        char* error                   = NULL;
        bool valid =
            jwtc_validate(invalid_token, secret, 0, &validated_claims, &error);
        free(error);
        json_object_put(validated_claims);

        if (valid) {
                printf("FAIL: Malformed token should fail\n");
                return 1;
        }
        printf("PASS (expected failure)\n");
        return 0;
}

static int test_null_inputs(void) {
        printf("Test: Handle null inputs\n");
        char* error = NULL;
        char* token = jwtc_generate(NULL, 3600, NULL, &error);
        if (token) {
                printf("FAIL: Generate with nulls should fail\n");
                free(token);
                return 1;
        }
        free(error);

        json_object* claims = NULL;
        error               = NULL;
        bool valid          = jwtc_validate(NULL, "secret", 0, &claims, &error);
        free(error);
        json_object_put(claims);
        if (valid) {
                printf("FAIL: Validate with nulls should fail\n");
                return 1;
        }
        printf("PASS (expected failures)\n");
        return 0;
}

int main(void) {
        int failures = 0;

        failures += test_generate_and_validate();
        failures += test_invalid_secret();
        failures += test_expired_token();
        failures += test_invalid_format();
        failures += test_null_inputs();

        if (failures == 0) {
                printf("All tests passed!\n");
                return 0;
        } else {
                printf("%d test(s) failed.\n", failures);
                return 1;
        }
}

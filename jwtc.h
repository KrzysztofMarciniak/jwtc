#ifndef JWTC_H
#define JWTC_H
#include <json-c/json.h>
#include <stdbool.h>

// Generate an HS256 JWT. Caller must free the returned string and error (if
// non-NULL).
char* jwtc_generate(const char* secret, int expiry_seconds, json_object* claims,
                    char** error);

// Validate an HS256 JWT and extract claims. Caller must free claims (with
// json_object_put) and error (if non-NULL).
bool jwtc_validate(const char* token, const char* secret,
                   int time_offset_seconds, json_object** claims, char** error);

#endif// JWTC_H

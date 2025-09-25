# jwtc

A simple C library for generating and validating HS256 JWTs using json-c and OpenSSL.

## Dependencies

- json-c
- OpenSSL

## Install on Ubuntu/Debian:
```shell
sudo apt install libjson-c-dev libssl-dev
```

## Build

Uses Ninja (`build.ninja`).

Build library:

```shell
ninja
```
Run tests:

```shell
ninja test; ./test
```

## Install

For system-wide installation, use the provided `install.sh` script (make executable with `chmod +x install.sh`):

```shell
sudo ./install.sh
```

After installation, link projects with `-ljwtc -ljson-c -lcrypto`.

## Usage

Include `jwtc.h` and link `-ljwtc -ljson-c -lcrypto`.

### Generate Token
```c
#include "jwtc.h"
#include <json-c/json.h>

json_object *claims = json_object_new_object();
json_object_object_add(claims, "sub", json_object_new_string("user"));

char *error = NULL;
char *token = jwtc_generate("secret", 3600, claims, &error);
json_object_put(claims);

if (token) {
    printf("%s\n", token);
    free(token);
} else {
    printf("Error: %s\n", error);
    free(error);
}

```
### Validate Token

``` c
json_object *claims = NULL;
char *error = NULL;
if (jwtc_validate(token, "secret", 0, &claims, &error)) {
    printf("Valid: %s\n", json_object_to_json_string(claims));
    json_object_put(claims);
} else {
    printf("Invalid: %s\n", error);
    free(error);
}
```
### API

(`char *jwtc_generate(const char *secret, int expiry_seconds, json_object *claims, char **error);`)
(`bool jwtc_validate(const char *token, const char *secret, int time_offset_seconds, json_object **claims, char **error);`)

#### Free returned strings and json_object_put claims.

# jwtc
<img width="250" height="250" alt="jwtc" src="https://github.com/user-attachments/assets/36cc8253-0547-4896-b2f0-cdd59c44af6b" />

A simple C library for generating and validating HS256 JWTs using json-c and OpenSSL.

| Feature | **jwtc** | **[libjwt](https://github.com/benmcollins/libjwt)** |
| :--- | :--- | :--- |
| **Simplicity** | Simple | Extensive |
| **Dependencies** | json-c, OpenSSL, [ninja](https://github.com/ninja-build/ninja) | Jansson, OpenSSL , CMake |
| **Language** | C | C |
| **Supported Algorithms** | HS256 | Multiple, including HS256, RS256, ES256, etc. |
| **API** | Small, only generate and validate. | Comprehensive, including key management, custom headers, etc. |
| **Installation** | Manual build and install script | Standard build process |
| **License** | MIT | MPL-2.0 
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

## Clean

Clean compiled files.

```shell
ninja clean
```

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

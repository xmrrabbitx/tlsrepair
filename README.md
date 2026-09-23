# tlsrepair

`tlsrepair` is a C library for repairing **incomplete TLS certificate chains** using the **Authority Information Access (AIA)** extension.

It is designed for applications using **libcurl** and **OpenSSL** where a remote server does not provide all required intermediate certificates.

Instead of disabling TLS verification for the final connection, `tlsrepair` discovers missing intermediate certificates through AIA, downloads them, verifies their issuer relationships, verifies the resulting certificate path against the system trust store, and provides the discovered intermediates to OpenSSL during the final TLS verification.

## Features

* Detects incomplete TLS certificate chains
* Reads AIA `caIssuers` extensions
* Downloads missing intermediate certificates
* Supports multiple intermediate certificates
* Cryptographically verifies downloaded certificates before using them
* Uses the system OpenSSL trust store
* Keeps TLS peer verification enabled for the final request
* Keeps hostname verification enabled
* Works with libcurl
* Supports HTTP proxies
* Provides both static and shared libraries
* CMake package support

## How It Works

When a server provides an incomplete certificate chain, `tlsrepair` first obtains the certificates provided by the server and attempts normal certificate verification.

If verification fails because an intermediate certificate is missing, the library follows the AIA `caIssuers` information in the current certificate.

```text
Server
  │
  │  Incomplete certificate chain
  ▼
Server certificates
  │
  ▼
Verify against system trust store
  │
  │  Missing intermediate
  ▼
AIA caIssuers URL
  │
  ▼
Download issuer certificate
  │
  ▼
Verify issuer relationship
  │
  ▼
Add intermediate to verification chain
  │
  ▼
Verify against system trust store
  │
  ├── Missing another intermediate
  │        │
  │        └── Repeat AIA process
  │
  ▼
Chain verification succeeds
  │
  ▼
Configure OpenSSL/libcurl
  │
  ▼
Final HTTPS request
```

The important distinction is that `tlsrepair` does **not** modify the certificate chain sent by the server.

Instead, the missing intermediate certificates discovered through AIA are made available to OpenSSL as additional certificates during TLS certificate verification.

Conceptually:

```text
Server sends:

    Server Certificate
           │
           ▼
    [Missing Intermediate]
           │
           ▼
       Root CA


tlsrepair provides:

    Server Certificate
           │
           ▼
    AIA Intermediate
           │
           ▼
       Root CA
           │
           ▼
    System Trust Store
```

The final TLS connection still performs normal certificate and hostname verification.

## Requirements

* C11
* CMake 3.16 or newer
* libcurl
* OpenSSL

## Installation

Clone the repository:

```bash
git clone https://github.com/xmrrabbitx/tlsrepair.git
cd tlsrepair
```

Configure the project:

```bash
cmake -S . -B build
```

Build:

```bash
cmake --build build
```

Install:

```bash
sudo cmake --install build
```

The default installation installs the library and headers under `/usr/local`.

## Using tlsrepair with CMake

After installation, use `find_package()` in your project CMakeLists.txt:

```cmake
cmake_minimum_required(VERSION 3.16)

project(myapp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(tlsrepair REQUIRED)

add_executable(myapp
    src/main.c
)

target_link_libraries(
    myapp
    PRIVATE
        tlsrepair::tlsrepair
)
```

Then include the public header:

```c
#include <tlsrepair/tlsrepair.h>
```

## Basic Usage

A minimal application looks like this:

```c
#include <stdio.h>
#include <curl/curl.h>
#include <tlsrepair/tlsrepair.h>

static size_t write_callback(
    void *contents,
    size_t size,
    size_t nmemb,
    void *userp
)
{
    (void)userp;

    return fwrite(
        contents,
        size,
        nmemb,
        stdout
    );
}

int main(void)
{
    if(!tlsrepair_global_init()){
        return 1;
    }

    TLSRepair *repair =
        tlsrepair_create(
            "https://example.com"
        );

    if(!repair){
        tlsrepair_global_cleanup();
        return 1;
    }

    if(!tlsrepair_prepare(repair)){
        tlsrepair_destroy(repair);
        tlsrepair_global_cleanup();
        return 1;
    }

    CURL *curl =
        tlsrepair_curl(repair);

    if(!curl){
        tlsrepair_destroy(repair);
        tlsrepair_global_cleanup();
        return 1;
    }

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    CURLcode result =
        curl_easy_perform(curl);

    if(result != CURLE_OK){
        fprintf(
            stderr,
            "curl error: %s\n",
            curl_easy_strerror(result)
        );
    }

    tlsrepair_destroy(repair);
    tlsrepair_global_cleanup();

    return result == CURLE_OK ? 0 : 1;
}
```

## API

### `tlsrepair_global_init`

Initializes the global libcurl state.

```c
int tlsrepair_global_init(void);
```

Returns:

```text
1  Success
0  Failure
```

Call this before creating `TLSRepair` objects.

---

### `tlsrepair_global_cleanup`

Cleans up the global libcurl state.

```c
void tlsrepair_global_cleanup(void);
```

Call this after all `TLSRepair` objects have been destroyed.

---

### `tlsrepair_create`

Creates a TLS repair object.

```c
TLSRepair *tlsrepair_create(
    const char *url
);
```

The URL is used during certificate discovery and repair.

Returns `NULL` on failure.

---

### `tlsrepair_set_proxy`

Configures a proxy for the internal libcurl connection.

```c
int tlsrepair_set_proxy(
    TLSRepair *repair,
    const char *proxy
);
```

Example:

```c
tlsrepair_set_proxy(
    repair,
    "http://127.0.0.1:8080"
);
```

Pass `NULL` to remove the configured proxy.

Returns:

```text
1  Success
0  Failure
```

---

### `tlsrepair_prepare`

Inspects and repairs the TLS certificate chain.

```c
int tlsrepair_prepare(
    TLSRepair *repair
);
```

Returns:

```text
1  Success
0  Failure
```

A successful result means the internal libcurl connection is configured and ready for the application's final HTTP request.

---

### `tlsrepair_curl`

Returns the libcurl easy handle used by the repair object.

```c
CURL *tlsrepair_curl(
    TLSRepair *repair
);
```

The application can use this handle to configure and perform its actual HTTP request.

For example:

```c
CURL *curl =
    tlsrepair_curl(repair);

curl_easy_setopt(
    curl,
    CURLOPT_HTTPGET,
    1L
);

curl_easy_setopt(
    curl,
    CURLOPT_WRITEFUNCTION,
    write_callback
);

curl_easy_perform(curl);
```

The application is responsible for the final HTTP request and response handling.

---

### `tlsrepair_destroy`

Destroys a TLS repair object and releases its resources.

```c
void tlsrepair_destroy(
    TLSRepair *repair
);
```

## Request Ownership

`tlsrepair` handles **TLS certificate discovery and repair**, not the application's HTTP logic.

The application remains responsible for:

* HTTP method
* Request headers
* Request body
* Cookies
* Response callback
* Response processing
* HTTP status handling
* `curl_easy_perform()`

This allows the library to be used with applications that need different HTTP behaviors.

```text
Application
    │
    ├── Create TLSRepair
    │
    ├── Configure proxy (optional)
    │
    ├── tlsrepair_prepare()
    │
    ├── tlsrepair_curl()
    │
    ├── Configure HTTP request
    │
    ├── Configure response handling
    │
    └── curl_easy_perform()
             │
             ▼
        HTTPS connection
             │
             ▼
      TLS certificate verification
             │
             ▼
       AIA intermediates
```

## TLS Verification

During certificate discovery and AIA certificate retrieval, the library temporarily disables TLS certificate verification.

This is necessary because the server may initially provide an incomplete certificate chain, and the AIA certificate itself may need to be retrieved before normal verification can succeed.

The downloaded AIA certificate is **not trusted merely because it was downloaded**.

Before it is used, `tlsrepair` verifies the issuer relationship cryptographically. The resulting certificate path is then verified against the system trust store.

The final HTTPS request is performed with normal TLS verification enabled:

```text
CURLOPT_SSL_VERIFYPEER = 1
CURLOPT_SSL_VERIFYHOST = 2
```

The discovered intermediate certificates are supplied to OpenSSL during certificate verification.

Therefore, the library does **not** solve an incomplete certificate chain by permanently disabling TLS verification.

## Static and Shared Libraries

The project builds both:

```text
libtlsrepair.a
libtlsrepair.so
```

The shared library can be used through:

```cmake
target_link_libraries(
    myapp
    PRIVATE
        tlsrepair::tlsrepair
)
```

The static library is available through:

```cmake
target_link_libraries(
    myapp
    PRIVATE
        tlsrepair::tlsrepair_static
)
```

## Limitations

`tlsrepair` currently focuses on repairing missing intermediate certificates using AIA.

It does not:

* Disable TLS verification for the final request
* Replace an invalid or expired server certificate
* Replace an untrusted root certificate
* Ignore hostname verification
* Modify the system CA store
* Modify the certificate chain sent by the server
* Act as a general-purpose HTTP client

A server must provide usable AIA information for certificates that need to be discovered automatically.

The AIA URL must use a supported HTTP or HTTPS scheme.

## Thread Safety

A `TLSRepair` object should not be used concurrently from multiple threads.

Separate `TLSRepair` objects can be used by separate threads.

```text
Thread 1 → TLSRepair A
Thread 2 → TLSRepair B
Thread 3 → TLSRepair C
```

Do not share the same repair object between concurrent operations.

## Testing

The project includes test executables.

Build the project:

```bash
cmake -S . -B build
cmake --build build
```

Run the tests:

```bash
./build/tlsrepair_test_static
```

or:

```bash
./build/tlsrepair_test_shared
```

## License

This project is licensed under the MIT License.
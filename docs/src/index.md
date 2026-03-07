# CloudBase.jl Documentation

GitHub Repo: [https://github.com/JuliaServices/CloudBase.jl](https://github.com/JuliaServices/CloudBase.jl)

Welcome to CloudBase.jl! A simple, yet comprehensive foundation for interacting with common cloud providers in Julia.

## Installation

You can install CloudBase by typing the following in the Julia REPL:
```julia
] add CloudBase 
```

followed by 
```julia
using CloudBase
```
to load the package.

## Overview 

The CloudBase.jl package provides a set of foundational functionality for interacting with the most common
cloud providers. The AWS and Azure integrations are mature today, while GCP support is being added incrementally.
It specifically aims to *do* the following:
  * Handle common credential scenarios, including the following in order of precedence:
    * Allow manually provided credentials by user
    * Loading credentials from cloud-idiomatic environment variables
    * Loading credentials from cloud-idiomatic config/credential files
    * Inspecting current host environment for additional credential options (EC2, ECS task, etc.)
  * Handles automatic refresh attempts of credentials when they are close to expiring
  * Provides custom HTTP.jl clients that includes layers to set appropriate default keyword arguments
    for specific cloud configurations and handles request "signing" according to cloud-specific algorithms

The package specifically *does not* aim to do any of the following:
  * Cloud-specific error handling/parsing for specific codes/problems
  * URL/header/query parameter/request body validation of arguments for specific cloud service operations

The core of the package then, is in 3 *non*-exported modules (that you can import yourself if so desired):
  * `CloudBase.AWS`: provides `AWS.get`, `AWS.put`, `AWS.post`, `AWS.request` etc. as wrappers to corresponding `HTTP` methods
  * `CloudBase.Azure`: provides `Azure.get`, `Azure.put`, `Azure.post`, `Azure.request` etc. as wrappers to corresponding `HTTP` methods
  * `CloudBase.GCP`: provides `GCP.get`, `GCP.put`, `GCP.post`, `GCP.request` etc. as wrappers to corresponding `HTTP` methods; `main` currently supports explicit bearer tokens, `service_account`, `authorized_user`, and file/url-based `external_account` credentials, plus metadata-server credentials and Cloud Storage XML HMAC interop via `AWS4-HMAC-SHA256`

That means *using* this packages behavior is basically like dropping in a cloud-specific module call in place
of where you would have been calling HTTP.jl, like:

```julia
import CloudBase: AWS

function get_file(url, creds)
    # previously tried to do manual header auth signing manually or something and then call HTTP.get
    # now can just call AWS.get w/ creds and it will do the request signing automatically
    # right before the request is sent on the wire
    return AWS.get(url; service="S3", region="us-west-1", access_key_id=creds.id, secret_access_key=creds.secret)
end
```

## Testing

The default test suite is intentionally mock-heavy and secretless. For GCP specifically, service-account,
authorized-user, external-account, metadata-server, and Cloud Storage HMAC flows are all covered by local
HTTP mocks in `test/runtests.jl`.

There is also an opt-in live GCP smoke test that performs a real object write/read/delete round-trip against
an existing bucket when `CLOUDBASE_RUN_GCP_LIVE_TESTS=1` is set. The required environment variables are:

```bash
export CLOUDBASE_RUN_GCP_LIVE_TESTS=1
export CLOUDBASE_GCP_LIVE_BUCKET=<existing-bucket>
# choose one credential path:
export CLOUDBASE_GCP_LIVE_ACCESS_TOKEN=<token>
# or:
export CLOUDBASE_GCP_LIVE_CREDENTIALS_FILE=/path/to/credentials.json
# or:
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
# or:
export CLOUDBASE_GCP_LIVE_HMAC_ACCESS_ID=<id>
export CLOUDBASE_GCP_LIVE_HMAC_SECRET=<secret>
```

`CLOUDBASE_GCP_LIVE_QUOTA_PROJECT` can also be provided when the request path needs a user-project header.

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

CloudBase requires Julia 1.10 or later and HTTP.jl 2.6.1 or later. HTTP.jl
2.6.1 preserves trace-time signing changes when automatic HTTP/2 negotiation
falls back to HTTP/1.1. Authenticated and public requests therefore use
automatic protocol selection. You can pass `protocol=:h1` or `protocol=:h2`
to require one protocol.

Authenticated `open` supports bodyless `GET` and `HEAD` requests. It disables
automatic redirects because HTTP.jl's streaming API cannot re-sign a changed
redirect URL. Make a new signed request to the redirect target instead. Use the
`open do` form when the metrics callback must observe request completion.

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

## MinIO object retention

Use the existing `CloudBase.AWS` request methods to configure MinIO object
locking. Object locking requires a versioned bucket with locking enabled.
Creating a bucket with `x-amz-bucket-object-lock-enabled: true` also enables
versioning. The credentials must permit bucket creation, retention configuration,
and the object operations below.

This executable example starts a temporary local MinIO server. It sets a one-day
GOVERNANCE retention rule, uploads one object, and checks that its protected
version remains readable after an ordinary delete. `Minio.with` stops the server
and removes its temporary data when the callback ends.

```@example object_lock
using CloudBase, HTTP, Base64, MD5
const AWS = CloudBase.AWS

CloudBase.CloudTest.Minio.with() do config
    bucket = AWS.Bucket("retention-example";
        host="http://127.0.0.1:$(config.port)")
    options = (; credentials=config.credentials, service="s3", region="us-east-1")
    checksum(body) = ["Content-MD5" => base64encode(md5(body))]

    AWS.put(bucket.baseurl, ["x-amz-bucket-object-lock-enabled" => "true"];
        options...)
    rule = """
    <ObjectLockConfiguration>
      <ObjectLockEnabled>Enabled</ObjectLockEnabled>
      <Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule>
    </ObjectLockConfiguration>
    """
    AWS.put(bucket.baseurl, checksum(rule), rule;
        query=Dict("object-lock" => ""), options...)

    url = bucket.baseurl * "record.txt"
    data = "retained record"
    uploaded = AWS.put(url, checksum(data), data; options...)
    version = HTTP.header(uploaded, "x-amz-version-id")
    @assert !isempty(version)
    version_query = Dict("versionId" => version)

    # Deleting the protected version fails without a governance bypass.
    denied = AWS.delete(url; query=version_query, status_exception=false, options...)
    @assert denied.status in (400, 403)

    # An ordinary delete creates a marker; it does not remove the protected version.
    deleted = AWS.delete(url; options...)
    @assert HTTP.header(deleted, "x-amz-delete-marker") == "true"
    retained = AWS.get(url; query=version_query, options...)
    @assert String(retained.body) == data
    println("The protected version remains readable.")
end
```

Retention protects each object version. A new upload can create another version
of the same key. An ordinary delete hides the object behind a delete marker;
use its version ID to read the retained data. Users with the required governance
bypass permission can explicitly bypass GOVERNANCE retention.
See the [MinIO object-lock documentation](https://docs.min.io/aistor/administration/object-locking-and-immutability/)
for retention modes and server requirements.

This recipe was validated with the bundled `minio_jll` 2.0.0+0 binary, which
reports `DEVELOPMENT.GOGET`. Its rejection status is 400; other servers can use
403. This is a local MinIO example, not validation of live AWS S3 or multipart
uploads. It supplies `Content-MD5` explicitly; CloudBase does not add that header
automatically.

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

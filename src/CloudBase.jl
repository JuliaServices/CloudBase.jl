module CloudBase

export CloudTest

using Dates, Base64, Random, Sockets
using HTTP, URIs, SHA, MD5, LoggingExtras, Figgy, JSON, OpenSSL

"""
    CloudCredentials

Abstract type that specific cloud providers subtype to represent
a "credentials" object. This is passed to cloud request methods
as the `credentials` keyword argument and is used to authenticate
cloud requests. See [`AWS.Credentials`](@ref) and
[`Azure.Credentials`](@ref) for examples.
"""
abstract type CloudCredentials end

"""
    AbstractStore

Abstract type that specific cloud providers subtype to represent
a "store". This is used to construct cloud urls and perform
operations on cloud objects. See [`AWS.Bucket`](@ref) and
[`Azure.Container`](@ref) for examples.
"""
abstract type AbstractStore end

_some(x, y) = x === nothing ? y : x

# utility to check if an ip:port can be connected to
function canconnect(ip, port, timeout=0.01)
    tcp = Sockets.TCPSocket()
    try
        Sockets.connect!(tcp, ip, port)
        sleep(timeout)
        return tcp.status == Base.StatusOpen
    catch
        return false
    finally
        close(tcp)
    end
end

# expiration check for credential types that support refreshing
expired(x) = x.expiration !== nothing && Dates.now(Dates.UTC) > (x.expiration - x.expireThreshold)


# HTTP 2 request bodies are typed objects rather than raw bytes, and `HTTP.isbytes`
# no longer exists. Signing needs the payload bytes for its SHA-256/HMAC.
requestbodybytes(request::HTTP.Request) = bodybytes(request.body)
bodybytes(body::HTTP.BytesBody) = body.data
bodybytes(::HTTP.EmptyBody) = UInt8[]
bodybytes(body::AbstractVector{UInt8}) = body
bodybytes(body::AbstractString) = Vector{UInt8}(codeunits(String(body)))
bodybytes(body) = Vector{UInt8}(codeunits(HTTP.escapeuri(body)))

include("aws.jl")
include("azure.jl")
include("gcp.jl")


"""
    CloudBase.prerequest(method::String)

Hook called once before each cloud request. The default is a no-op; add a method to
observe requests. Previously configured through `PREREQUEST_CALLBACK[]`, which required
a `FunctionWrapper` to stay type stable - a plain function needs no such indirection and
stays resolvable under `--trim=safe`.
"""
prerequest(method::String) = nothing

"""
    CloudBase.metrics(method, request_failed, request_retries, request_duration_ms,
                      bytes_sent, bytes_received, status)

Hook called once after each cloud request completes. The default is a no-op; add a method
to record metrics.

The HTTP 1 client exposed per-connection counters through `req.context`; the HTTP 2 client
does not populate that, so the error-category counters and connect/read/write durations the
old signature carried are no longer obtainable and have been dropped rather than reported
as zeros.
"""
metrics(method::String, request_failed::Bool, request_retries::Int, request_duration_ms::Float64, bytes_sent::Int, bytes_received::Int, status::Int) = nothing

mutable struct CloudRequestStats
    start::Float64
    retries::Int
    bytes_sent::Int
    bytes_received::Int
    status::Int
end

CloudRequestStats() = CloudRequestStats(time(), 0, 0, 0, 0)

_content_length(x) = x === nothing ? 0 : (x isa Integer ? Int(x) : 0)

"""
    cloudlayer(provider::Symbol)

Client middleware that installs an HTTP 2 `trace` callback which signs every request
attempt and records metrics.

Signing happens on `RequestEvent`, which HTTP emits immediately before *each* attempt,
so a retried request is re-signed with a fresh timestamp - the same guarantee the HTTP 1
stream layer provided. `HTTP.Request` no longer carries a `.url`, so the absolute URL is
taken from the event.
"""
function cloudlayer(provider::Symbol)
    return function(handler)
        return function(method, url, headers=Pair{String,String}[], body=nothing;
                        credentials=nothing, trace=nothing, logexceptionalduration::Int=0, kw...)
            stats = CloudRequestStats()
            prerequest(String(method))
            tracer = function(ev)
                if ev isa HTTP.RequestEvent
                    uri = URI(ev.url)
                    if provider === :aws
                        awssign!(ev.request, uri; credentials, kw...)
                    elseif provider === :awsv2
                        awssignv2!(ev.request, uri; credentials, kw...)
                    elseif provider === :azure
                        azuresign!(ev.request, uri; credentials, kw...)
                    elseif provider === :gcp
                        gcpsign!(ev.request, uri; credentials, kw...)
                    end
                    stats.bytes_sent = _content_length(ev.request.content_length)
                elseif ev isa HTTP.RetryEvent
                    stats.retries += 1
                elseif ev isa HTTP.ResponseHeadEvent
                    stats.status = ev.response.status
                    stats.bytes_received = _content_length(ev.response.content_length)
                elseif ev isa HTTP.DoneEvent
                    dur = (time() - stats.start) * 1000
                    if logexceptionalduration > 0 && div(dur, 1000) > logexceptionalduration
                        @warn "Exceptionally long cloud request:" total_duration_ms=dur method=method url=ev.url
                    end
                    metrics(String(method), ev.err !== nothing, stats.retries, dur,
                            stats.bytes_sent, stats.bytes_received, stats.status)
                end
                # compose with any caller-supplied trace rather than displacing it
                trace === nothing || trace(ev)
                return nothing
            end
            return handler(method, url, headers, body; trace=tracer, kw...)
        end
    end
end

"""
    CloudBase.AWS

Submodule that contains a custom HTTP.jl client for performing AWS requests.
For authenticated requests, an [`AWS.Credentials`](@ref) object should be passed
as the `credentials` keyword argument. Otherwise, the request methods operate
just like the `HTTP` equivalents and supports all the same keyword arguments.
"""
module AWS

using HTTP
import ..cloudlayer, ..AWSCredentials, ..AbstractStore, ..AWS_DEFAULT_REGION

HTTP.@client (cloudlayer(:aws),)

const DOCS = """
    AWS.get(url, headers, body; credentials, awsv2=false, kw...)
    AWS.put(url, headers, body; kw...)
    AWS.post(url, headers, body; kw...)
    AWS.delete(url, headers, body; kw...)
    AWS.head(url, headers; kw...)
    AWS.patch(url, headers, body; kw...)
    AWS.request(method, url, headers, body; kw...)
    AWS.open(method, url, headers[, body]; kw...)

HTTP.jl client methods that additionally *each* take a `credentials` keyword argument,
which should be an `AWS.Credentials` object. To have AWSV2 request signing instead of AWSV4,
pass `awsv2=true`. If the `credentials` object was inferred from the environment and is set
to expire soon, it will be refreshed automatically.

Otherwise, these methods operate exactly like their `HTTP.method` counterparts, accepting
all the same positional and keyword arguments.

Note that due to the nature of AWS signing requirements, streaming request bodies are not supported.
"""
for method in (:get, :put, :post, :delete, :head, :patch, :request, :open)
    @eval begin
        @doc $DOCS AWS.$method(args...; kw...)
    end
end

"""
    CloudBase.AWS.Credentials([profile]; expireThreshold=Dates.Minute(5))
    CloudBase.AWS.Credentials(access_key_id, secret_access_key[, session_token])

Credentials object used for authenticating AWS requests. By default, calling `AWS.Credentials()` or
`AWS.Credentials(profile)`, will search the normal AWS credential locations (files, environment variables, etc.)
to find the access key and secret. Otherwise, the 2nd constructor allows providing the access key & secret directly,
ignoring any existing configurations. If a profile includes a `role_arn`, an STS request will be made with
source credentials to get temporary credentials. AWS EC2 and ECS credentials are also automatically detected and
retrieved. Temporary credentials via EC2, EC2, or role_arn that include expirations will automatically be refreshed
`expireThreshold` before expiration when a request is made.
"""
const Credentials = AWSCredentials

"""
    CloudBase.AWS.Bucket(name, [region="us-east-1"]; accelerate::Bool=false)

Object representation of an AWS storage bucket with the given `name`. If not provided,
the `region` is assumed to be "us-east-1". Aliased in the CloudStore.jl package as `S3.Bucket`.
If `accelerate=true` is passed, requests with the bucket will use the `bucket.s3-accelerate.amazonaws.com`
style url instead of the traditional `bucket.s3.amazonaws.com`.
"""
struct Bucket <: AbstractStore
    name::String
    baseurl::String

    function Bucket(name::String, region::String=AWS_DEFAULT_REGION; accelerate::Bool=false, host::Union{Nothing, String}=nothing)
        baseurl = host === nothing ? "https://$name.s3$(accelerate ? "-accelerate" : "").$region.amazonaws.com/" : "$host/$name/"
        return new(name, baseurl)
    end
end

end # module AWS

"""
    CloudBase.Azure

Submodule that contains a custom HTTP.jl client for performing Azure requests.
For authenticated requests, an [`Azure.Credentials`](@ref) object should be passed
as the `credentials` keyword argument. Otherwise, the request methods operate
just like the `HTTP` equivalents and supports all the same keyword arguments.
"""
module Azure

using HTTP
import ..cloudlayer, ..AzureCredentials, ..AbstractStore

HTTP.@client (cloudlayer(:azure),)

const DOCS = """
    Azure.get(url, headers, body; credentials, kw...)
    Azure.put(url, headers, body; kw...)
    Azure.post(url, headers, body; kw...)
    Azure.delete(url, headers, body; kw...)
    Azure.head(url, headers; kw...)
    Azure.patch(url, headers, body; kw...)
    Azure.request(method, url, headers, body; kw...)
    Azure.open(method, url, headers[, body]; kw...)

HTTP.jl client methods that additionally *each* take a `credentials` keyword argument,
which should be an `Azure.Credentials` object. If the `credentials` object was inferred
from the environment and is set to expire soon, it will be refreshed automatically.

Otherwise, these methods operate exactly like their `HTTP.method` counterparts, accepting
all the same positional and keyword arguments.
"""
for method in (:get, :put, :post, :delete, :head, :patch, :request, :open)
    @eval begin
        @doc $DOCS Azure.$method(args...; kw...)
    end
end

"""
    CloudBase.Azure.Credentials(; expireThreshold=Dates.Minute(5))
    CloudBase.Azure.Credentials(account, shared_key)
    CloudBase.Azure.Credentials(access_token)

Credentials object used for authenticating Azure requests. By default, calling `Azure.Credentials()`
will search the normal Azure credential locations (files, environment variables, etc.)
to find the account, shared key, or access_token. Otherwise, the 2nd constructor allows providing the
account & shared key or access token directly, ignoring any existing configurations. Azure VM credentials
are also automatically detected and retrieved. Temporary credentials via Azure VM that include expirations
will automatically be refreshed `expireThreshold` before expiration when a request is made.
"""
const Credentials = AzureCredentials

"""
    CloudBase.Azure.Container(name, account)

Object representation of an Azure storage bucket with the given `name` and `account`.
Aliased in the CloudStore.jl package as `Blobs.Container`.
"""
struct Container <: AbstractStore
    name::String
    baseurl::String

    function Container(name::String, account::String; host::Union{Nothing, String}=nothing)
        baseurl = host === nothing ? "https://$account.blob.core.windows.net/$name/" : "$host/$account/$name/"
        return new(name, baseurl)
    end
end

end # module Azure

"""
    CloudBase.GCP

Submodule that contains a custom HTTP.jl client for performing Google Cloud requests.
For authenticated requests, an explicit [`GCP.Credentials`](@ref) object can be passed
as the `credentials` keyword argument. Otherwise, the request methods operate just like
the `HTTP` equivalents and support all the same keyword arguments.
"""
module GCP

using HTTP
import ..cloudlayer, ..GCPCredentials, ..AbstractStore

HTTP.@client (cloudlayer(:gcp),)

const DOCS = """
    GCP.get(url, headers, body; credentials, kw...)
    GCP.put(url, headers, body; kw...)
    GCP.post(url, headers, body; kw...)
    GCP.delete(url, headers, body; kw...)
    GCP.head(url, headers; kw...)
    GCP.patch(url, headers, body; kw...)
    GCP.request(method, url, headers, body; kw...)
    GCP.open(method, url, headers[, body]; kw...)

HTTP.jl client methods that additionally *each* take a `credentials` keyword argument,
which should be a `GCP.Credentials` object. GCP credentials support explicit bearer
tokens, `service_account`, `authorized_user`, and file/url-based `external_account`
application credentials, metadata-server tokens on Google-managed compute, and
explicit Cloud Storage XML HMAC interop credentials.

Otherwise, these methods operate exactly like their `HTTP.method` counterparts, accepting
all the same positional and keyword arguments.
"""
for method in (:get, :put, :post, :delete, :head, :patch, :request, :open)
    @eval begin
        @doc $DOCS GCP.$method(args...; kw...)
    end
end

"""
    CloudBase.GCP.Credentials(access_token[, expiration]; expireThreshold=Dates.Minute(5))
    CloudBase.GCP.Credentials(access_id, secret; region="us-east-1", service="s3", expireThreshold=Dates.Minute(5))
    CloudBase.GCP.Credentials(; application_credentials_file=nothing, scopes=[...], expireThreshold=Dates.Minute(5))

Credentials object used for authenticating Google Cloud requests. An explicit bearer token
can be provided directly, or `GCP.Credentials()` can load a `service_account` application
credentials file, a well-known/local ADC file with `authorized_user` or `external_account`
credentials, or Google metadata-server credentials. A 2-string constructor is also
available for Cloud Storage XML HMAC interoperability using the documented
`AWS4-HMAC-SHA256` simple-migration path.
"""
const Credentials = GCPCredentials

"""
    CloudBase.GCP.Bucket(name)

Object representation of a Google Cloud Storage bucket using the XML API path-style
endpoint layout. This is intended to mirror the existing provider store types and
unblock downstream storage integrations.
"""
struct Bucket <: AbstractStore
    name::String
    baseurl::String

    function Bucket(name::String; host::Union{Nothing, String}=nothing)
        baseurl = host === nothing ? "https://storage.googleapis.com/$name/" : "$host/$name/"
        return new(name, baseurl)
    end
end

end # module GCP

include("CloudTest.jl")

end # module CloudBase

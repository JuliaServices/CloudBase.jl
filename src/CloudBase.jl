module CloudBase

export CloudTest
export CloudPool

using Dates, Base64, Random, Sockets
using HTTP, URIs, SHA, MD5, LoggingExtras, Figgy, JSON, OpenSSL, Reseau
import FunctionWrappers: FunctionWrapper

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

include("aws.jl")
include("azure.jl")
include("gcp.jl")
include("reseau_http.jl")


prerequest(method::String) = nothing
metrics(method::String, request_failed::Bool, request_retries::Int, request_duration_ms::Float64, bytes_sent::Int, bytes_received::Int, connect_errors::Int, io_errors::Int, status_errors::Int, timeout_errors::Int, connect_duration_ms::Float64, read_duration_ms::Float64, write_duration_ms::Float64) = nothing

const PREREQUEST_CALLBACK = Ref{FunctionWrapper{Nothing, Tuple{String}}}()
const METRICS_CALLBACK = Ref{FunctionWrapper{Nothing, Tuple{String, Bool, Int64, Float64, Int64, Int64, Int64, Int64, Int64, Int64, Float64, Float64, Float64}}}()

function cloudmetricslayer(handler)
    function cloudmetrics(req; logexceptionalduration::Int=0, kw...)
        failed = false
        bytes_sent = bytes_received = connect_errors = io_errors = status_errors = timeout_errors = 0
        connect_duration_ms = read_duration_ms = write_duration_ms = 0.0
        start = time()
        PREREQUEST_CALLBACK[](req.method)
        try
            resp = handler(req; kw...)
            bytes_received = get(req.context, :nbytes, 0)
            bytes_sent = get(req.context, :nbytes_written, 0)
            read_duration_ms = get(req.context, :read_duration_ms, 0.0)
            write_duration_ms = get(req.context, :write_duration_ms, 0.0)
            return resp
        catch
            failed = true
            rethrow()
        finally
            retries = get(req.context, :retryattempt, 0)
            connect_errors = get(req.context, :connect_errors, 0)
            io_errors = get(req.context, :io_errors, 0)
            status_errors = get(req.context, :status_errors, 0)
            timeout_errors = get(req.context, :timeout_errors, 0)
            connect_duration_ms = get(req.context, :connect_duration_ms, 0.0)
            dur = (time() - start) * 1000
            if logexceptionalduration > 0 && div(dur, 1000) > logexceptionalduration
                @warn "Exceptionally long cloud request:" total_duration_ms=dur method=req.method context=req.context
            end
            METRICS_CALLBACK[](req.method, failed, retries, dur, bytes_sent, bytes_received,
                connect_errors, io_errors, status_errors, timeout_errors,
                connect_duration_ms, read_duration_ms, write_duration_ms)
        end
    end
end

# custom stream layer to be included right before actual request
# is sent to ensure header timestamps are as correct as possible
function cloudsignlayer(handler)
    function cloudsign(stream; aws::Bool=false, awsv2::Bool=false, azure::Bool=false, gcp::Bool=false, kw...)
        req = stream.message.request
        if awsv2
            awssignv2!(req; kw...)
        elseif aws
            awssign!(req; kw...)
        end
        azure && azuresign!(req; kw...)
        gcp && gcpsign!(req; kw...)
        return handler(stream; kw...)
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
import ..CloudPool, ..cloudrequest, ..AWSCredentials, ..AbstractStore, ..AWS_DEFAULT_REGION

_default_readtimeout_kw(kw) = haskey(kw, :readtimeout) ? (; ) : (; readtimeout=300)
_is_headers_arg(x) = x isa AbstractDict || x isa AbstractVector

function _split_headers_body(args, headers, body)
    if isempty(args)
        return headers, body
    elseif length(args) == 1
        arg = args[1]
        if body !== nothing
            return arg, body
        elseif _is_headers_arg(arg)
            return arg, nothing
        else
            return headers, arg
        end
    elseif length(args) == 2
        return args[1], args[2]
    end
    throw(ArgumentError("expected at most two positional arguments after URL: headers and body"))
end

function request(method::AbstractString, url, headers=HTTP.Headers(), body=nothing; kw...)
    defaults = _default_readtimeout_kw(kw)
    return cloudrequest(method, url, headers, body; defaults..., kw..., aws=true)
end

get(url; headers=HTTP.Headers(), kw...) = request("GET", url, headers, nothing; kw...)
get(url, headers; kw...) = request("GET", url, headers, nothing; kw...)
head(url; headers=HTTP.Headers(), kw...) = request("HEAD", url, headers, nothing; kw...)
head(url, headers; kw...) = request("HEAD", url, headers, nothing; kw...)
function post(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("POST", url, headers, body; kw...)
end
function put(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("PUT", url, headers, body; kw...)
end
function patch(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("PATCH", url, headers, body; kw...)
end
function delete(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("DELETE", url, headers, body; kw...)
end
open(args...; kw...) = throw(ArgumentError("AWS.open is not supported by the Reseau-backed transport"))

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
import ..CloudPool, ..cloudrequest, ..AzureCredentials, ..AbstractStore

_default_readtimeout_kw(kw) = haskey(kw, :readtimeout) ? (; ) : (; readtimeout=300)
_is_headers_arg(x) = x isa AbstractDict || x isa AbstractVector

function _split_headers_body(args, headers, body)
    if isempty(args)
        return headers, body
    elseif length(args) == 1
        arg = args[1]
        if body !== nothing
            return arg, body
        elseif _is_headers_arg(arg)
            return arg, nothing
        else
            return headers, arg
        end
    elseif length(args) == 2
        return args[1], args[2]
    end
    throw(ArgumentError("expected at most two positional arguments after URL: headers and body"))
end

function _default_require_ssl_verification(url, kw)
    haskey(kw, :require_ssl_verification) && return kw[:require_ssl_verification]
    return String(HTTP.URI(url).host) != "127.0.0.1"
end

function request(method::AbstractString, url, headers=HTTP.Headers(), body=nothing; kw...)
    readtimeout_kw = _default_readtimeout_kw(kw)
    ssl_kw = haskey(kw, :require_ssl_verification) ? (; ) : (; require_ssl_verification=_default_require_ssl_verification(url, kw))
    return cloudrequest(method, url, headers, body; readtimeout_kw..., ssl_kw..., kw..., azure=true, aws=false, awsv2=false)
end

get(url; headers=HTTP.Headers(), kw...) = request("GET", url, headers, nothing; kw...)
get(url, headers; kw...) = request("GET", url, headers, nothing; kw...)
head(url; headers=HTTP.Headers(), kw...) = request("HEAD", url, headers, nothing; kw...)
head(url, headers; kw...) = request("HEAD", url, headers, nothing; kw...)
function post(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("POST", url, headers, body; kw...)
end
function put(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("PUT", url, headers, body; kw...)
end
function patch(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("PATCH", url, headers, body; kw...)
end
function delete(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("DELETE", url, headers, body; kw...)
end
open(args...; kw...) = throw(ArgumentError("Azure.open is not supported by the Reseau-backed transport"))

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
import ..CloudPool, ..cloudrequest, ..GCPCredentials, ..AbstractStore

_default_readtimeout_kw(kw) = haskey(kw, :readtimeout) ? (; ) : (; readtimeout=300)
_is_headers_arg(x) = x isa AbstractDict || x isa AbstractVector

function _split_headers_body(args, headers, body)
    if isempty(args)
        return headers, body
    elseif length(args) == 1
        arg = args[1]
        if body !== nothing
            return arg, body
        elseif _is_headers_arg(arg)
            return arg, nothing
        else
            return headers, arg
        end
    elseif length(args) == 2
        return args[1], args[2]
    end
    throw(ArgumentError("expected at most two positional arguments after URL: headers and body"))
end

function request(method::AbstractString, url, headers=HTTP.Headers(), body=nothing; kw...)
    defaults = _default_readtimeout_kw(kw)
    return cloudrequest(method, url, headers, body; defaults..., kw..., gcp=true, aws=false, awsv2=false, azure=false)
end

get(url; headers=HTTP.Headers(), kw...) = request("GET", url, headers, nothing; kw...)
get(url, headers; kw...) = request("GET", url, headers, nothing; kw...)
head(url; headers=HTTP.Headers(), kw...) = request("HEAD", url, headers, nothing; kw...)
head(url, headers; kw...) = request("HEAD", url, headers, nothing; kw...)
function post(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("POST", url, headers, body; kw...)
end
function put(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("PUT", url, headers, body; kw...)
end
function patch(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("PATCH", url, headers, body; kw...)
end
function delete(url, args...; headers=HTTP.Headers(), body=nothing, kw...)
    headers, body = _split_headers_body(args, headers, body)
    return request("DELETE", url, headers, body; kw...)
end
open(args...; kw...) = throw(ArgumentError("GCP.open is not supported by the Reseau-backed transport"))

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

function __init__()
    PREREQUEST_CALLBACK[] = prerequest
    METRICS_CALLBACK[] = metrics
    return
end

end # module CloudBase

const GCP_CONFIGS = Figgy.Store()
const GCP_DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
const GCP_APPLICATION_CREDENTIALS_ENV = "GOOGLE_APPLICATION_CREDENTIALS"
const GCP_JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
const GCP_DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token"
const GCP_DEFAULT_METADATA_ROOT = "http://metadata.google.internal"
const GCP_DEFAULT_SERVICE_ACCOUNT = "default"
const GCP_METADATA_TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/{service_account}/token"

abstract type GCPAuth end

struct AccessToken <: GCPAuth
    token::String
end

Base.show(io::IO, ::AccessToken) = print(io, "AccessToken(****)")

abstract type GCPSource end

struct StaticAuthSource <: GCPSource
    auth::GCPAuth
end

Base.show(io::IO, ::StaticAuthSource) = print(io, "StaticAuthSource(...)")

struct ServiceAccountSource <: GCPSource
    client_email::String
    private_key::String
    token_uri::String
    private_key_id::String
end

function Base.show(io::IO, source::ServiceAccountSource)
    print(io, "ServiceAccountSource(")
    print(io, "client_email=", source.client_email, ",")
    print(io, "private_key=****,")
    print(io, "token_uri=", source.token_uri, ",")
    print(io, "private_key_id=", isempty(source.private_key_id) ? "" : "****", ")")
end

struct MetadataSource <: GCPSource
    root::String
    service_account::String
end

Base.show(io::IO, source::MetadataSource) = print(io, "MetadataSource($(source.root), $(source.service_account))")

mutable struct GCPCredentials <: CloudCredentials
    lock::ReentrantLock
    source::GCPSource
    auth::GCPAuth
    expiration::Union{Nothing, DateTime}
    expireThreshold::Dates.Period
    scopes::Vector{String}
end

GCPCredentials(source::GCPSource, auth::GCPAuth, expiration, expireThreshold, scopes::Vector{String}) =
    GCPCredentials(ReentrantLock(), source, auth, expiration, expireThreshold, scopes)

function Base.show(io::IO, creds::GCPCredentials)
    print(io, "GCPCredentials(")
    print(io, "source=")
    show(io, creds.source)
    print(io, ",auth=")
    show(io, creds.auth)
    print(io, ",expiration=", creds.expiration, ",")
    print(io, "expireThreshold=", creds.expireThreshold, ",")
    print(io, "scopes=", creds.scopes, ")")
end

function GCPCredentials(access_token::String, expiration=nothing; expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES))
    auth = AccessToken(access_token)
    return GCPCredentials(StaticAuthSource(auth), auth, expiration, expireThreshold, copy(scopes))
end

function GCPCredentials(source::ServiceAccountSource; expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES))
    return GCPCredentials(source, AccessToken(""), Dates.now(Dates.UTC) - Dates.Second(1), expireThreshold, copy(scopes))
end

function GCPCredentials(source::MetadataSource; expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES))
    return GCPCredentials(source, AccessToken(""), Dates.now(Dates.UTC) - Dates.Second(1), expireThreshold, copy(scopes))
end

function GCPCredentials(; application_credentials_file::Union{Nothing, String}=nothing, expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES))
    application_credentials_file === nothing || return loadApplicationCredentials(application_credentials_file; expireThreshold, scopes)
    return gcpLoadConfig!(copy(scopes), expireThreshold)
end

base64urlencode(x::AbstractString) = base64urlencode(codeunits(x))
base64urlencode(x::Base.CodeUnits{UInt8, String}) = base64urlencode(Vector{UInt8}(x))
base64urlencode(x::AbstractVector{UInt8}) = rstrip(replace(base64encode(x), '+' => '-', '/' => '_'), '=')

function base64urldecode(x::AbstractString)
    str = replace(x, '-' => '+', '_' => '/')
    padding = mod(-ncodeunits(str), 4)
    return base64decode(str * repeat("=", padding))
end

gcpConfigEnvironmentVariables() = Figgy.kmap(Figgy.EnvironmentVariables(),
    GCP_APPLICATION_CREDENTIALS_ENV => "application_credentials_file"; select=true
)

function tokenExpiration(expires_in)
    seconds = expires_in isa Integer ? Int(expires_in) : parse(Int, String(expires_in))
    return Dates.unix2datetime(floor(Int, time()) + seconds)
end

function gcpLoadConfig!(scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES), expireThreshold=Dates.Minute(5))
    delete!(GCP_CONFIGS, "application_credentials_file")
    Figgy.load!(GCP_CONFIGS, gcpConfigEnvironmentVariables())
    credentials = if haskey(GCP_CONFIGS, "application_credentials_file")
        loadApplicationCredentials(GCP_CONFIGS["application_credentials_file"]; expireThreshold, scopes)
    elseif metadataAvailable()
        loadMetadataCredentials(; expireThreshold, scopes)
    else
        throw(ArgumentError("could not discover GCP credentials; set `$GCP_APPLICATION_CREDENTIALS_ENV` to a service-account credential file or run on a host with Google metadata credentials"))
    end
    Figgy.load!(GCP_CONFIGS, "credentials" => credentials)
    return credentials
end

function metadataAvailable(root::String=GCP_DEFAULT_METADATA_ROOT)
    uri = HTTP.URI(root)
    host = something(uri.host, "")
    isempty(host) && return false
    port = uri.port == "" ? (uri.scheme == "https" ? 443 : 80) : parse(Int, uri.port)
    return canconnect(host, port)
end

function jsonfield(obj, field::String)
    haskey(obj, field) || throw(ArgumentError("missing `$field` in GCP credential payload"))
    return obj[field]
end

function loadApplicationCredentials(path::AbstractString; expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES))
    isfile(path) || throw(ArgumentError("GCP credentials file does not exist: `$path`"))
    config = JSON.parse(read(path))
    kind = String(jsonfield(config, "type"))
    kind == "service_account" || throw(ArgumentError("unsupported GCP application credentials type `$kind`; only `service_account` is supported in this phase"))
    source = ServiceAccountSource(
        String(jsonfield(config, "client_email")),
        String(jsonfield(config, "private_key")),
        haskey(config, "token_uri") ? String(config["token_uri"]) : GCP_DEFAULT_TOKEN_URI,
        haskey(config, "private_key_id") ? String(config["private_key_id"]) : "",
    )
    credentials = GCPCredentials(source; expireThreshold, scopes)
    refresh!(credentials)
    return credentials
end

function loadMetadataCredentials(; root::String=GCP_DEFAULT_METADATA_ROOT, service_account::String=GCP_DEFAULT_SERVICE_ACCOUNT, expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES))
    credentials = GCPCredentials(MetadataSource(root, service_account); expireThreshold, scopes)
    refresh!(credentials)
    return credentials
end

function getCredentials(x::GCPCredentials)
    Base.@lock x.lock begin
        if shouldRefresh(x)
            refresh!(x)
        end
        return x.auth
    end
end

shouldRefresh(x::GCPCredentials) = !(x.source isa StaticAuthSource) && (x.auth isa AccessToken && (isempty(x.auth.token) || expired(x)))

refresh!(x::GCPCredentials) = refresh!(x, x.source)
refresh!(x::GCPCredentials, ::StaticAuthSource) = x

function refresh!(x::GCPCredentials, source::ServiceAccountSource)
    body = HTTP.escapeuri(Dict(
        "grant_type" => GCP_JWT_GRANT_TYPE,
        "assertion" => createServiceAccountAssertion(source, x.scopes),
    ))
    resp = HTTP.post(source.token_uri, ["Content-Type" => "application/x-www-form-urlencoded"], body)
    payload = JSON.parse(resp.body)
    x.auth = AccessToken(String(jsonfield(payload, "access_token")))
    x.expiration = tokenExpiration(jsonfield(payload, "expires_in"))
    return x
end

function refresh!(x::GCPCredentials, source::MetadataSource)
    url = metadataTokenURL(source)
    resp = HTTP.get(url, ["Metadata-Flavor" => "Google"])
    payload = JSON.parse(resp.body)
    x.auth = AccessToken(String(jsonfield(payload, "access_token")))
    x.expiration = tokenExpiration(jsonfield(payload, "expires_in"))
    return x
end

function metadataTokenURL(source::MetadataSource)
    path = replace(GCP_METADATA_TOKEN_PATH, "{service_account}" => source.service_account)
    return string(rstrip(source.root, '/'), path)
end

function createServiceAccountAssertion(source::ServiceAccountSource, scopes::Vector{String})
    issued_at = floor(Int, time())
    expires_at = issued_at + 3600
    header = isempty(source.private_key_id) ?
        JSON.json((alg="RS256", typ="JWT")) :
        JSON.json((alg="RS256", typ="JWT", kid=source.private_key_id))
    payload = JSON.json((
        iss=source.client_email,
        scope=join(scopes, ' '),
        aud=source.token_uri,
        exp=expires_at,
        iat=issued_at,
    ))
    signing_input = string(base64urlencode(header), '.', base64urlencode(payload))
    signature = signRS256(source.private_key, signing_input)
    return string(signing_input, '.', base64urlencode(signature))
end

function signRS256(private_key::String, message::String)
    key = OpenSSL.EvpPKey(private_key)
    ctx = OpenSSL.EvpDigestContext()
    digest = OpenSSL.EvpSHA256()
    if ccall((:EVP_DigestSignInit, OpenSSL.libcrypto), Cint,
            (OpenSSL.EvpDigestContext, Ptr{Cvoid}, OpenSSL.EvpDigest, Ptr{Cvoid}, OpenSSL.EvpPKey),
            ctx, C_NULL, digest, C_NULL, key) != 1
        throw(OpenSSL.OpenSSLError())
    end
    data = Vector{UInt8}(codeunits(message))
    GC.@preserve data begin
        if ccall((:EVP_DigestSignUpdate, OpenSSL.libcrypto), Cint,
                (OpenSSL.EvpDigestContext, Ptr{UInt8}, Csize_t),
                ctx, pointer(data), length(data)) != 1
            throw(OpenSSL.OpenSSLError())
        end
    end
    siglen = Ref{Csize_t}(0)
    if ccall((:EVP_DigestSignFinal, OpenSSL.libcrypto), Cint,
            (OpenSSL.EvpDigestContext, Ptr{UInt8}, Ref{Csize_t}),
            ctx, C_NULL, siglen) != 1
        throw(OpenSSL.OpenSSLError())
    end
    signature = Vector{UInt8}(undef, siglen[])
    GC.@preserve signature begin
        if ccall((:EVP_DigestSignFinal, OpenSSL.libcrypto), Cint,
                (OpenSSL.EvpDigestContext, Ptr{UInt8}, Ref{Csize_t}),
                ctx, pointer(signature), siglen) != 1
            throw(OpenSSL.OpenSSLError())
        end
    end
    resize!(signature, siglen[])
    return signature
end

function reloadGCECredentials!(root=nothing; service_account::String=GCP_DEFAULT_SERVICE_ACCOUNT, expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES))
    credentials = loadMetadataCredentials(; root=something(root, GCP_DEFAULT_METADATA_ROOT), service_account, expireThreshold, scopes)
    Figgy.load!(GCP_CONFIGS, "credentials" => credentials)
    return credentials
end

function gcpsign!(request::HTTP.Request; credentials::Union{Nothing, GCPCredentials}=nothing, kw...)
    credentials === nothing && return
    auth = getCredentials(credentials)
    auth isa AccessToken || throw(ArgumentError("unsupported GCP credentials type `$(typeof(auth))`"))
    HTTP.removeheader(request, "Authorization")
    HTTP.setheader(request, "Authorization" => "Bearer $(auth.token)")
    return
end

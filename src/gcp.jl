const GCP_CONFIGS = Figgy.Store()
const GCP_DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
const GCP_IMPERSONATION_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
const GCP_APPLICATION_CREDENTIALS_ENV = "GOOGLE_APPLICATION_CREDENTIALS"
const GCP_JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
const GCP_REFRESH_TOKEN_GRANT_TYPE = "refresh_token"
const GCP_TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
const GCP_REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
const GCP_DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token"
const GCP_DEFAULT_STS_TOKEN_URI = "https://sts.googleapis.com/v1/token"
const GCP_DEFAULT_METADATA_ROOT = "http://metadata.google.internal"
const GCP_DEFAULT_SERVICE_ACCOUNT = "default"
const GCP_METADATA_TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/{service_account}/token"

abstract type GCPAuth end

struct AccessToken <: GCPAuth
    token::String
end

Base.show(io::IO, ::AccessToken) = print(io, "AccessToken(****)")

struct HMACKey <: GCPAuth
    access_id::String
    secret::String
    region::String
    service::String
end

function Base.show(io::IO, key::HMACKey)
    print(io, "HMACKey(")
    print(io, "access_id=****,secret=****,region=", key.region, ",service=", key.service, ")")
end

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

struct AuthorizedUserSource <: GCPSource
    client_id::String
    client_secret::String
    refresh_token::String
    token_uri::String
end

function Base.show(io::IO, source::AuthorizedUserSource)
    print(io, "AuthorizedUserSource(")
    print(io, "client_id=****,client_secret=****,refresh_token=****,token_uri=", source.token_uri, ")")
end

abstract type ExternalCredentialSource end

struct ExternalFileSource <: ExternalCredentialSource
    file::String
    format_type::String
    subject_token_field_name::String
end

Base.show(io::IO, source::ExternalFileSource) = print(io, "ExternalFileSource($(source.file), $(source.format_type))")

struct ExternalURLSource <: ExternalCredentialSource
    url::String
    headers::Vector{Pair{String, String}}
    format_type::String
    subject_token_field_name::String
end

Base.show(io::IO, source::ExternalURLSource) = print(io, "ExternalURLSource($(source.url), $(source.format_type))")

struct ExternalAccountSource <: GCPSource
    audience::String
    subject_token_type::String
    token_uri::String
    service_account_impersonation_url::String
    service_account_token_lifetime_seconds::Int
    workforce_pool_user_project::String
    credential_source::ExternalCredentialSource
end

function Base.show(io::IO, source::ExternalAccountSource)
    print(io, "ExternalAccountSource(")
    print(io, "audience=", source.audience, ",")
    print(io, "subject_token_type=", source.subject_token_type, ",")
    print(io, "token_uri=", source.token_uri, ",")
    print(io, "service_account_impersonation_url=", source.service_account_impersonation_url, ",")
    print(io, "service_account_token_lifetime_seconds=", source.service_account_token_lifetime_seconds, ",")
    print(io, "workforce_pool_user_project=", source.workforce_pool_user_project, ",")
    print(io, "credential_source=")
    show(io, source.credential_source)
    print(io, ")")
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
    quota_project_id::String
end

GCPCredentials(source::GCPSource, auth::GCPAuth, expiration, expireThreshold, scopes::Vector{String}, quota_project_id::String) =
    GCPCredentials(ReentrantLock(), source, auth, expiration, expireThreshold, scopes, quota_project_id)

function Base.show(io::IO, creds::GCPCredentials)
    print(io, "GCPCredentials(")
    print(io, "source=")
    show(io, creds.source)
    print(io, ",auth=")
    show(io, creds.auth)
    print(io, ",expiration=", creds.expiration, ",")
    print(io, "expireThreshold=", creds.expireThreshold, ",")
    print(io, "scopes=", creds.scopes, ",")
    print(io, "quota_project_id=", creds.quota_project_id, ")")
end

function GCPCredentials(access_token::String, expiration=nothing; expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES), quota_project_id::String="")
    auth = AccessToken(access_token)
    return GCPCredentials(StaticAuthSource(auth), auth, expiration, expireThreshold, copy(scopes), quota_project_id)
end

function GCPCredentials(access_id::String, secret::String; region::String=AWS_DEFAULT_REGION, service::String="s3", expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES), quota_project_id::String="")
    auth = HMACKey(access_id, secret, region, service)
    return GCPCredentials(StaticAuthSource(auth), auth, nothing, expireThreshold, copy(scopes), quota_project_id)
end

function GCPCredentials(source::GCPSource; expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES), quota_project_id::String="")
    source isa StaticAuthSource && throw(ArgumentError("refreshable GCP sources must not be wrapped in `StaticAuthSource`"))
    return GCPCredentials(source, AccessToken(""), Dates.now(Dates.UTC) - Dates.Second(1), expireThreshold, copy(scopes), quota_project_id)
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

function wellKnownApplicationCredentialsFile()
    if Sys.iswindows()
        return joinpath(get(ENV, "APPDATA", homedir()), "gcloud", "application_default_credentials.json")
    end
    return joinpath(homedir(), ".config", "gcloud", "application_default_credentials.json")
end

function tokenExpiration(expires_in)
    seconds = expires_in isa Integer ? Int(expires_in) : parse(Int, String(expires_in))
    return Dates.unix2datetime(floor(Int, time()) + seconds)
end

function parseRFC3339(value)
    str = String(value)
    str = endswith(str, 'Z') ? chop(str) : str
    if occursin('.', str)
        parts = split(str, '.'; limit=2)
        frac = parts[2]
        frac = frac[1:min(lastindex(frac), 3)]
        frac = rpad(frac, 3, '0')
        return DateTime(string(parts[1], '.', frac), dateformat"yyyy-mm-ddTHH:MM:SS.s")
    end
    return DateTime(str, dateformat"yyyy-mm-ddTHH:MM:SS")
end

function gcpLoadConfig!(scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES), expireThreshold=Dates.Minute(5))
    delete!(GCP_CONFIGS, "application_credentials_file")
    Figgy.load!(GCP_CONFIGS, gcpConfigEnvironmentVariables())
    credentials = if haskey(GCP_CONFIGS, "application_credentials_file")
        loadApplicationCredentials(GCP_CONFIGS["application_credentials_file"]; expireThreshold, scopes)
    else
        well_known = wellKnownApplicationCredentialsFile()
        if isfile(well_known)
            loadApplicationCredentials(well_known; expireThreshold, scopes)
        elseif metadataAvailable()
            loadMetadataCredentials(; expireThreshold, scopes)
        else
            throw(ArgumentError("could not discover GCP credentials; set `$GCP_APPLICATION_CREDENTIALS_ENV`, create a well-known gcloud ADC file, or run on a host with Google metadata credentials"))
        end
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

quotaProjectID(config) = haskey(config, "quota_project_id") ? String(config["quota_project_id"]) :
    haskey(config, "workforce_pool_user_project") ? String(config["workforce_pool_user_project"]) : ""

function credentialSourceFormat(source)
    haskey(source, "format") || return ("text", "")
    format = source["format"]
    format_type = String(jsonfield(format, "type"))
    subject_token_field_name = haskey(format, "subject_token_field_name") ? String(format["subject_token_field_name"]) : ""
    return (format_type, subject_token_field_name)
end

function parseExternalCredentialSource(config)
    source = jsonfield(config, "credential_source")
    format_type, subject_token_field_name = credentialSourceFormat(source)
    if haskey(source, "file")
        return ExternalFileSource(String(source["file"]), format_type, subject_token_field_name)
    elseif haskey(source, "url")
        headers = haskey(source, "headers") ? Pair{String, String}[String(k) => String(v) for (k, v) in pairs(source["headers"])] : Pair{String, String}[]
        return ExternalURLSource(String(source["url"]), headers, format_type, subject_token_field_name)
    end
    throw(ArgumentError("unsupported `external_account` credential source; expected `credential_source.file` or `credential_source.url`"))
end

function loadApplicationCredentials(path::AbstractString; expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES))
    isfile(path) || throw(ArgumentError("GCP credentials file does not exist: `$path`"))
    config = JSON.parse(read(path))
    kind = String(jsonfield(config, "type"))
    quota_project_id = quotaProjectID(config)
    credentials = if kind == "service_account"
        source = ServiceAccountSource(
            String(jsonfield(config, "client_email")),
            String(jsonfield(config, "private_key")),
            haskey(config, "token_uri") ? String(config["token_uri"]) : GCP_DEFAULT_TOKEN_URI,
            haskey(config, "private_key_id") ? String(config["private_key_id"]) : "",
        )
        GCPCredentials(source; expireThreshold, scopes, quota_project_id)
    elseif kind == "authorized_user"
        source = AuthorizedUserSource(
            String(jsonfield(config, "client_id")),
            String(jsonfield(config, "client_secret")),
            String(jsonfield(config, "refresh_token")),
            haskey(config, "token_uri") ? String(config["token_uri"]) : GCP_DEFAULT_TOKEN_URI,
        )
        GCPCredentials(source; expireThreshold, scopes, quota_project_id)
    elseif kind == "external_account"
        impersonation = haskey(config, "service_account_impersonation") ? config["service_account_impersonation"] : nothing
        lifetime = impersonation === nothing || !haskey(impersonation, "token_lifetime_seconds") ? 0 : Int(impersonation["token_lifetime_seconds"])
        source = ExternalAccountSource(
            String(jsonfield(config, "audience")),
            String(jsonfield(config, "subject_token_type")),
            haskey(config, "token_url") ? String(config["token_url"]) : GCP_DEFAULT_STS_TOKEN_URI,
            haskey(config, "service_account_impersonation_url") ? String(config["service_account_impersonation_url"]) : "",
            lifetime,
            haskey(config, "workforce_pool_user_project") ? String(config["workforce_pool_user_project"]) : "",
            parseExternalCredentialSource(config),
        )
        GCPCredentials(source; expireThreshold, scopes, quota_project_id)
    else
        throw(ArgumentError("unsupported GCP application credentials type `$kind`; expected `service_account`, `authorized_user`, or `external_account`"))
    end
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

function refresh!(x::GCPCredentials, source::AuthorizedUserSource)
    body = HTTP.escapeuri(Dict(
        "client_id" => source.client_id,
        "client_secret" => source.client_secret,
        "refresh_token" => source.refresh_token,
        "grant_type" => GCP_REFRESH_TOKEN_GRANT_TYPE,
    ))
    resp = HTTP.post(source.token_uri, ["Content-Type" => "application/x-www-form-urlencoded"], body)
    payload = JSON.parse(resp.body)
    x.auth = AccessToken(String(jsonfield(payload, "access_token")))
    x.expiration = tokenExpiration(jsonfield(payload, "expires_in"))
    return x
end

function refresh!(x::GCPCredentials, source::ExternalAccountSource)
    subject_token = loadSubjectToken(source.credential_source)
    payload = JSON.parse(exchangeExternalAccountToken(source, subject_token, x.scopes).body)
    access_token = String(jsonfield(payload, "access_token"))
    expiration = tokenExpiration(jsonfield(payload, "expires_in"))
    if !isempty(source.service_account_impersonation_url)
        access_token, expiration = impersonateServiceAccount(source, access_token, x.scopes)
    end
    x.auth = AccessToken(access_token)
    x.expiration = expiration
    if isempty(x.quota_project_id)
        x.quota_project_id = source.workforce_pool_user_project
    end
    return x
end

function refresh!(x::GCPCredentials, source::MetadataSource)
    resp = HTTP.get(metadataTokenURL(source), ["Metadata-Flavor" => "Google"])
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

function loadSubjectToken(source::ExternalFileSource)
    isfile(source.file) || throw(ArgumentError("external_account credential source file does not exist: `$(source.file)`"))
    return parseSubjectToken(read(source.file), source.format_type, source.subject_token_field_name)
end

function loadSubjectToken(source::ExternalURLSource)
    resp = HTTP.get(source.url, source.headers)
    return parseSubjectToken(resp.body, source.format_type, source.subject_token_field_name)
end

function parseSubjectToken(value::AbstractVector{UInt8}, format_type::String, subject_token_field_name::String)
    return parseSubjectToken(String(value), format_type, subject_token_field_name)
end

function parseSubjectToken(value::AbstractString, format_type::String, subject_token_field_name::String)
    if format_type == "text"
        token = String(strip(value))
    elseif format_type == "json"
        isempty(subject_token_field_name) && throw(ArgumentError("json external_account credential sources must set `format.subject_token_field_name`"))
        token = String(jsonfield(JSON.parse(value), subject_token_field_name))
    else
        throw(ArgumentError("unsupported external_account credential source format `$format_type`; expected `text` or `json`"))
    end
    isempty(token) && throw(ArgumentError("external_account subject token must not be empty"))
    return token
end

function exchangeExternalAccountToken(source::ExternalAccountSource, subject_token::String, scopes::Vector{String})
    scope = isempty(source.service_account_impersonation_url) ? join(scopes, ' ') : join(GCP_IMPERSONATION_SCOPES, ' ')
    body = JSON.json(Dict(
        "audience" => source.audience,
        "grantType" => GCP_TOKEN_EXCHANGE_GRANT_TYPE,
        "requestedTokenType" => GCP_REQUESTED_TOKEN_TYPE,
        "scope" => scope,
        "subjectToken" => subject_token,
        "subjectTokenType" => source.subject_token_type,
    ))
    return HTTP.post(source.token_uri, ["Content-Type" => "application/json"], body)
end

function impersonateServiceAccount(source::ExternalAccountSource, access_token::String, scopes::Vector{String})
    body = Dict{String, Any}("scope" => copy(scopes))
    if source.service_account_token_lifetime_seconds > 0
        body["lifetime"] = string(source.service_account_token_lifetime_seconds, "s")
    end
    resp = HTTP.post(source.service_account_impersonation_url,
        ["Content-Type" => "application/json", "Authorization" => "Bearer $access_token"],
        JSON.json(body))
    payload = JSON.parse(resp.body)
    return String(jsonfield(payload, "accessToken")), parseRFC3339(jsonfield(payload, "expireTime"))
end

function reloadGCECredentials!(root=nothing; service_account::String=GCP_DEFAULT_SERVICE_ACCOUNT, expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES))
    credentials = loadMetadataCredentials(; root=something(root, GCP_DEFAULT_METADATA_ROOT), service_account, expireThreshold, scopes)
    Figgy.load!(GCP_CONFIGS, "credentials" => credentials)
    return credentials
end

function gcpsign!(request::HTTP.Request; credentials::Union{Nothing, GCPCredentials}=nothing, kw...)
    credentials === nothing && return
    auth = getCredentials(credentials)
    if auth isa AccessToken
        HTTP.removeheader(request, "Authorization")
        HTTP.setheader(request, "Authorization" => "Bearer $(auth.token)")
        if !isempty(credentials.quota_project_id)
            HTTP.setheader(request, "x-goog-user-project" => credentials.quota_project_id)
        end
    elseif auth isa HMACKey
        if !isempty(credentials.quota_project_id)
            HTTP.setheader(request, "x-amz-project-id" => credentials.quota_project_id)
        end
        awssign!(request; service=auth.service, region=auth.region, credentials=AWSCredentials(auth.access_id, auth.secret), kw...)
    else
        throw(ArgumentError("unsupported GCP credentials type `$(typeof(auth))`"))
    end
    return
end

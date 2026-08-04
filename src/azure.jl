const AZURE_CONFIGS = Figgy.Store()

abstract type AzureAuth end

struct SharedKey <: AzureAuth
    account::String
    key::String
end

Base.show(io::IO, x::SharedKey) = print(io, "SharedKey($(x.account), ****)")

struct AccessToken <: AzureAuth
    token::String # token acquired via oauth flow
end

Base.show(io::IO, ::AccessToken) = print(io, "AccessToken(****)")

struct SASToken <: AzureAuth
    token::String # just the query string of a SAS uri; url?sas_token

    SASToken(str) = new(lstrip(String(str), '?'))
end

Base.show(io::IO, ::SASToken) = print(io, "SASToken(****)")

mutable struct AzureCredentials <: CloudCredentials
    lock::ReentrantLock
    auth::AzureAuth
    expiration::Union{Nothing, DateTime}
    expireThreshold::Dates.Period
end

AzureCredentials(auth::AzureAuth, expiration=nothing, expireThreshold=Dates.Minute(5)) =
    AzureCredentials(ReentrantLock(), auth, expiration, expireThreshold)

AzureCredentials(account::String, key::String; kw...) = AzureCredentials(SharedKey(account, key); kw...)
AzureCredentials(token::String; kw...) = AzureCredentials(contains(token, "&") ? SASToken(token) : AccessToken(token); kw...)

function getCredentials(x::AzureCredentials)
    Base.@lock x.lock begin
        if expired(x)
            azureLoadConfig!(x.expireThreshold)
            creds = AZURE_CONFIGS["credentials"]
            x.auth = creds.auth
            x.expiration = creds.expiration
        end
        return x.auth
    end
end

function AzureCredentials(load::Bool=true; expireThreshold=Dates.Minute(5))
    load && azureLoadConfig!(expireThreshold)
    return AZURE_CONFIGS["credentials"]
end

azureConfigEnvironmentVariables() = Figgy.kmap(Figgy.EnvironmentVariables(),
    "AZURE_CLIENT_ID" => "client_id",
    "AZURE_CLIENT_SECRET" => "client_secret",
    "AZURE_TENANT_ID" => "tenant_id",
    "AZURE_DEFAULTS_GROUP" => "group",
    "AZURE_DEFAULTS_LOCATION" => "location",
    "AZURE_STORAGE_ACCOUNT" => "account",
    "AZURE_STORAGE_KEY" => "key",
    "AZURE_STORAGE_SAS_TOKEN" => "sas_token",
    "AZURE_SAS_TOKEN" => "sas_token",
    "SAS_TOKEN" => "sas_token",
    "AZURE_STORAGE_ACCESS_TOKEN" => "access_token"; select=true
)

azureVMConfig() = Figgy.kmap(Figgy.EnvironmentVariables(),
    "AZURE_TOKEN_OBJECT_ID" => "object_id",
    "AZURE_TOKEN_CLIENT_ID" => "client_id",
    "AZURE_TOKEN_MI_RES_ID" => "mi_res_id",; select=true
)

# Azure IMDS reports `expires_on` as seconds-since-epoch, but as a JSON string; other
# sources may supply a DateTime or nothing. Normalise all of them to Union{Nothing,DateTime}.
azureExpiration(::Nothing) = nothing
azureExpiration(x::DateTime) = x
azureExpiration(x::Real) = Dates.unix2datetime(x)
function azureExpiration(x::AbstractString)
    isempty(x) && return nothing
    secs = tryparse(Float64, x)
    secs !== nothing && return Dates.unix2datetime(secs)
    dt = tryparse(DateTime, rstrip(String(x), 'Z'))
    dt === nothing && throw(ArgumentError("invalid Azure credential expiration: $(repr(x))"))
    return dt
end

function azureLoadConfig!(expireThreshold=Dates.Minute(5))
    # on each fresh load, we want to clear out potentially stale credential fields
    # note that each load, we *will* replace AZURE_CONFIGS["credentials"]
    # so we still keep track of their history bundled together
    delete!(AZURE_CONFIGS, "sas_token")
    delete!(AZURE_CONFIGS, "access_token")
    delete!(AZURE_CONFIGS, "account")
    delete!(AZURE_CONFIGS, "key")
    delete!(AZURE_CONFIGS, "expiration")
    Figgy.load!(AZURE_CONFIGS, azureVMConfig())
    configFile = joinpath(homedir(), ".azure", "config")
    Figgy.load!(AZURE_CONFIGS,
        azureConfigEnvironmentVariables(),
        Figgy.IniFile(configFile, "defaults"),
        Figgy.IniFile(configFile, "storage"),
        AzureVMCredentialsSource(),
        #TODO: support oauth w/ client id/client secret
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/scenario-daemon-acquire-token?tabs=dotnet
    )
    # after doing a single config "load", we want to bundle the credentials
    # together as one object in AZURE_CONFIGS, so we know they all came "together"
    # IMDS returns expires_on as a JSON string, and Figgy parses JSON scalars as
    # Strings, so unix2datetime must not be handed the raw value
    exp = get(AZURE_CONFIGS, "expiration", "")
    expiration = azureExpiration(exp)
    if haskey(AZURE_CONFIGS, "sas_token")
        auth = SASToken(AZURE_CONFIGS["sas_token"])
    elseif haskey(AZURE_CONFIGS, "access_token")
        auth = AccessToken(AZURE_CONFIGS["access_token"])
    elseif haskey(AZURE_CONFIGS, "account") && haskey(AZURE_CONFIGS, "key")
        auth = SharedKey(AZURE_CONFIGS["account"], AZURE_CONFIGS["key"])
    else
        auth = SharedKey("", "")
    end
    Figgy.load!(AZURE_CONFIGS, "credentials" => AzureCredentials(auth, expiration, expireThreshold))
    return
end

struct AzureVMCredentialsSource <: Figgy.FigSource
    vmHost::String # for testing purposes
end
AzureVMCredentialsSource() = AzureVMCredentialsSource("http://169.254.169.254")

function Figgy.load(x::AzureVMCredentialsSource)
    host = x.vmHost
    query = Dict(
        "api-version" => "2018-02-01",
        "resource" => "https://storage.azure.com/",
        "object_id" => get(AZURE_CONFIGS, "object_id", ""),
        "client_id" => get(AZURE_CONFIGS, "client_id", ""),
        "mi_res_id" => get(AZURE_CONFIGS, "mi_res_id", ""),
    )
    filtered_query = Pair{String, String}[k => v for (k, v) in query if v != ""]
    resp = HTTP.get("$host/metadata/identity/oauth2/token", ["Metadata" => "true"]; query=filtered_query)
    return Figgy.kmap(Figgy.JsonObject(resp.body),
        "access_token" => "access_token",
        "expires_on" => "expiration",
    )
end
reloadAzureVMCredentials!(vmHost::String) = Figgy.load!(AZURE_CONFIGS, AzureVMCredentialsSource(vmHost))
reloadAzureVMCredentials!() = Figgy.load!(AZURE_CONFIGS, AzureVMCredentialsSource())

const AZURE_API_VERSION = "2021-04-10"
const RFC1123Format = dateformat"e, dd u yyyy HH:MM:SS \G\M\T"
trimall2(x) = strip(replace(x, r"[\s]{2,}" => " "))

function combineParams(pairs)
    io = IOBuffer()
    cur_key = ""
    vals = String[]
    for (k, v) in pairs
        if k != cur_key
            if !isempty(vals)
                print(io, "\n$cur_key:$(join(sort!(vals), ","))")
            end
            cur_key = k
            empty!(vals)
        end
        push!(vals, v)
    end
    if !isempty(vals)
        print(io, "\n$cur_key:$(join(sort!(vals), ","))")
    end
    return String(take!(io))
end

function azuresign!(request::HTTP.Request, url::URI; credentials=nothing, addMd5::Bool=true, kw...)
    # if credentials not provided, assume public access
    credentials === nothing && return
    # we're going to set Authorization header, so delete it if present
    HTTP.removeheader(request, "Authorization")
    dt = Dates.now(Dates.UTC)
    requestDateTime = Dates.format(dt, RFC1123Format)
    HTTP.setheader(request, "x-ms-date" => requestDateTime)
    HTTP.setheader(request, "x-ms-version" => AZURE_API_VERSION)
    # if addMd5 && request.body isa Union{Vector{UInt8}, String}
    #     hash = bytes2hex(md5(request.body))
    #     @show hash
    #     HTTP.setheader(request, "Content-MD5" => bytes2hex(md5(request.body)))
    # end
    # determine credentials
    creds = getCredentials(credentials)
    if creds isa AccessToken
        HTTP.setheader(request, "Authorization" => "Bearer $(creds.token)")
        return
    elseif creds isa SASToken
        query = URIs.queryparampairs(url)
        toks = URIs.queryparampairs(creds.token)
        for pair in toks
            i = findfirst(x -> x.first == pair.first, query)
            i === nothing ? push!(query, pair) : (query[i] = pair)
        end
        signed_url = URI(url; query)
        path = isempty(signed_url.path) ? "/" : String(signed_url.path)
        request.target = isempty(signed_url.query) ? path : "$path?$(signed_url.query)"
        return
    end

    # shared access key auth header computation
    @assert creds isa SharedKey
    # compute signature
    msheaders = filter(x -> startswith(lowercase(x.first), "x-ms-"), request.headers)
    headers = sort!(map(x -> lowercase(x.first) => trimall2(x.second), msheaders), by=x->x.first)
    canonicalHeaders = join(map(x -> "$(x.first):$(x.second)", headers), "\n")
    pairs = sort!(map(x -> lowercase(x.first) => x.second, queryparampairs(url)), by=x->x.first)
    canonicalQueryString = combineParams(pairs)
    path = isempty(url.path) ? "/" : url.path
    canonicalResource = "/$(creds.account)$(path)$canonicalQueryString"
    len = HTTP.header(request, "Content-Length")
    if isempty(len) && request.content_length > 0
        len = string(request.content_length)
    end
    stringToSign = """$(request.method)
    $(HTTP.header(request, "Content-Encoding"))
    $(HTTP.header(request, "Content-Language"))
    $(len == "0" ? "" : len)
    $(HTTP.header(request, "Content-MD5"))
    $(HTTP.header(request, "Content-Type"))
    
    $(HTTP.header(request, "If-Modified-Since"))
    $(HTTP.header(request, "If-Match"))
    $(HTTP.header(request, "If-None-Match"))
    $(HTTP.header(request, "If-Unmodified-Since"))
    $(HTTP.header(request, "Range"))
    $canonicalHeaders
    $canonicalResource"""
    # println("######################## string to sign")
    # println(stringToSign)
    # println("########################")
    # @show creds
    signature = base64encode(hmac_sha256(base64decode(creds.key), stringToSign))
    # @show signature
    header = "SharedKey $(creds.account):$signature"
    HTTP.setheader(request, "Authorization" => header)
    return
end

include("azure_sas.jl")

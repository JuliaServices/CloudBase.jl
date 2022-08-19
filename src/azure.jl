const AZURE_CONFIGS = Figgy.Store()

abstract type AzureAuth end

struct SharedKey <: AzureAuth
    account::String
    key::String
end

Base.show(io::IO, x::SharedKey) = print(io, "SharedKey($(x.account), ****)")

struct AccessToken <: AzureAuth
    token::String
end

Base.show(io::IO, ::AccessToken) = print(io, "AccessToken(****)")

mutable struct AzureCredentials <: CloudAccount
    lock::ReentrantLock
    auth::AzureAuth
    expiration::Union{Nothing, DateTime}
    expireThreshold::Dates.Period
end

AzureCredentials(auth::AzureAuth, expiration=nothing, expireThreshold=Dates.Minute(5)) =
    AzureCredentials(ReentrantLock(), auth, expiration, expireThreshold)

AzureCredentials(account::String, key::String) = AzureCredentials(SharedKey(account, key))
AzureCredentials(token::String) = AzureCredentials(AccessToken(token))

function credentials(x::AzureCredentials)
    Base.@lock x.lock begin
        if expired(x)
            creds = loadAndGetAzureCreds!()
            x.auth = creds.auth
            x.expiration = creds.expiration
        end
        return x.auth
    end
end

function loadAndGetAzureCreds!()
    azureLoadConfig!()
    exp = get(AZURE_CONFIGS, "expiration", "")
    expiration = exp === nothing ? exp : Dates.unix2datetime(exp)
    if haskey(AZURE_CONFIGS, "sas_token")
        return (auth=AccessToken(AZURE_CONFIGS["sas_token"]), expiration)
    elseif haskey(AZURE_CONFIGS, "account") && haskey(AZURE_CONFIGS, "key")
        return (auth=SharedKey(AZURE_CONFIGS["account"], AZURE_CONFIGS["key"]), expiration=nothing)
    else
        return nothing
    end
end

function AzureCredentials(; expireThreshold=Dates.Minute(5))
    creds = loadAndGetAzureCreds!()
    if creds === nothing
        error("No Azure credentials found in environment")
    end
    return AzureCredentials(creds.auth, creds.expiration, expireThreshold)
end

azureConfigEnvironmentVariables() = Figgy.kmap(Figgy.EnvironmentVariables(),
    "AZURE_CLIENT_ID" => "client_id",
    "AZURE_CLIENT_SECRET" => "client_secret",
    "AZURE_TENANT_ID" => "tenant_id",
    "AZURE_DEFAULTS_GROUP" => "group",
    "AZURE_DEFAULTS_LOCATION" => "location",
    "AZURE_STORAGE_ACCOUNT" => "account",
    "AZURE_STORAGE_KEY" => "key",
    "AZURE_STORAGE_SAS_TOKEN" => "sas_token"; select=true
)

azureVMConfig() = Figgy.kmap(Figgy.EnvironmentVariables(),
    "AZURE_TOKEN_OBJECT_ID" => "object_id",
    "AZURE_TOKEN_CLIENT_ID" => "client_id",
    "AZURE_TOKEN_MI_RES_ID" => "mi_res_id",; select=true
)

function azureLoadConfig!()
    Figgy.load!(AZURE_CONFIGS, azureVMConfig())
    configFile = joinpath(homedir(), ".azure", "config")
    Figgy.load!(AZURE_CONFIGS,
        azureConfigEnvironmentVariables(),
        Figgy.IniFile(configFile, "defaults"),
        Figgy.IniFile(configFile, "storage"),
        AzureVMCredentialsSource(),
        #TODO: support oauth w/ client id/client secret; need to run azurite as https
    )
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
    resp = HTTP.get("$host/metadata/identity/oauth2/token", ["Metadata" => "true"]; query=filter(x->x.second != "", query))
    return Figgy.kmap(Figgy.JsonObject(resp.body),
        "access_token" => "sas_token",
        "expires_on" => "expiration",
    )
end
reloadAzureVMCredentials!(vmHost=nothing) = Figgy.load!(AZURE_CONFIGS, AzureVMCredentialsSource(vmHost))

const AZURE_API_VERSION = "2020-04-08"
const RFC1123Format = dateformat"e, dd u yyyy HH:MM:SS \G\M\T"
trimall2(x) = strip(replace(x, r"[\s]{2,}" => " "))

function pairsToDict(pairs)
    d = Dict{String, Vector{String}}()
    for (k, v) in pairs
        vals = get!(() -> String[], d, k)
        push!(vals, v)
    end
    return d
end

function combineParams(params::Dict{String, Vector{String}})
    io = IOBuffer()
    for (k, v) in params
        sort!(v)
        print(io, "\n$k:$(join(v, ","))")
    end
    return String(take!(io))
end

function azuresign!(request::HTTP.Request; account=nothing, key=nothing, kw...)
    # if account not provided, assume public access
    account === nothing && return nothing
    # we're going to set Authorization header, so delete it if present
    HTTP.removeheader(request, "Authorization")
    dt = Dates.now(Dates.UTC)
    requestDateTime = Dates.format(dt, RFC1123Format)
    HTTP.setheader(request, "x-ms-date" => requestDateTime)
    HTTP.setheader(request, "x-ms-version" => AZURE_API_VERSION)
    # determine credentials
    creds = credentials(account)
    if creds isa AccessToken
        HTTP.setheader(request, "Authorization" => "Bearer $(creds.token)")
        return
    end

    # shared access key auth header computation
    @assert creds isa SharedKey
    # compute signature
    msheaders = filter(x -> startswith(lowercase(x.first), "x-ms-"), request.headers)
    headers = sort!(map(x -> lowercase(x.first) => trimall2(x.second), msheaders), by=x->x.first)
    canonicalHeaders = join(map(x -> "$(x.first):$(x.second)", headers), "\n")
    pairs = sort!(map(x -> lowercase(x.first) => x.second, collect(queryparampairs(request.url))), by=x->x.first)
    canonicalQueryString = combineParams(pairsToDict(pairs))
    canonicalResource = "/$(creds.account)$(request.url.path)$canonicalQueryString"
    len = HTTP.header(request, "Content-Length")
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

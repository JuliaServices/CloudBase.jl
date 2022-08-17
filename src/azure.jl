struct AzureCredentials <: CloudAccount
    account::String
    key::String
end

const AZURE_CONFIGS = Figgy.Store()

azureConfigEnvironmentVariables() = Figgy.kmap(Figgy.EnvironmentVariables(),
    "AZURE_DEFAULTS_GROUP" => "group",
    "AZURE_DEFAULTS_LOCATION" => "location",
    "AZURE_STORAGE_ACCOUNT" => "account",
    "AZURE_STORAGE_KEY" => "key",
    "AZURE_STORAGE_SAS_TOKEN" => "sas_token"; select=true
)

function azureLoadConfig!()
    configFile = joinpath(homedir(), ".azure", "config")
    Figgy.load!(AZURE_CONFIGS,
        azureConfigEnvironmentVariables(),
        Figgy.IniFile(configFile, "defaults"),
        Figgy.IniFile(configFile, "storage"),
    )
end

const AZURE_API_VERSION = "2016-05-31"
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
    # determine credentials
    account = _some(account, get(AZURE_CONFIGS, "account", nothing))
    account === nothing && ArgumentError("unable to determine Azure account for request; pass `account=X`")
    key = _some(key, get(AZURE_CONFIGS, "key", nothing))
    key === nothing && ArgumentError("unable to determine Azure key for request; pass `key=X`")
    creds = AzureCredentials(account, key)
    # we're going to set Authorization header, so delete it if present
    HTTP.removeheader(request, "Authorization")
    dt = Dates.now(Dates.UTC)
    requestDateTime = Dates.format(dt, RFC1123Format)
    HTTP.setheader(request, "x-ms-date" => requestDateTime)
    HTTP.setheader(request, "x-ms-version" => AZURE_API_VERSION)

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
    # @show stringToSign
    signature = base64encode(hmac_sha256(base64decode(creds.key), stringToSign))
    header = "SharedKey $(creds.account):$signature"
    HTTP.setheader(request, "Authorization" => header)
    return
end
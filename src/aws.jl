const AWS_CONFIGS = Figgy.Store()
# Each load rewrites the shared store, so loads run one at a time.
const AWS_LOAD_LOCK = ReentrantLock()
# Settings of the most recent load. Cleared before each load so that one profile never
# inherits another profile's role, region, or credentials.
const AWS_PROFILE_KEYS = ("profile", "aws_config_file", "aws_shared_credentials_file",
    "aws_access_key_id", "aws_secret_access_key", "aws_session_token", "expiration", "region",
    "role_arn", "source_profile", "credential_source", "web_identity_token_file",
    "role_session_name", "external_id", "duration_seconds")

mutable struct AWSCredentials <: CloudCredentials
    lock::ReloadLock
    profile::String # profile to reload; "" reloads the default chain
    access_key_id::String
    secret_access_key::String
    session_token::String
    expiration::Union{Nothing, DateTime}
    expireThreshold::Dates.Period
end


function Base.show(io::IO, creds::AWSCredentials)
    print(io, "AWSCredentials(")
    print(io, "profile=", creds.profile, ",")
    print(io, "access_key_id=", "****", ",")
    print(io, "secret_access_key=", "****", ",")
    print(io, "session_token=", "****", ",")
    print(io, "expiration=", creds.expiration, ",")
    print(io, "expireThreshold=", creds.expireThreshold, ")")
end

AWSCredentials(profile::String, access_key_id::String, secret_access_key::String, session_token::String, expiration, expireThreshold) =
    AWSCredentials(ReentrantLock(), profile, access_key_id, secret_access_key, session_token, expiration, expireThreshold)

# manual constructor
AWSCredentials(access_key_id::String, secret_access_key::String, session_token::String="", expiration=nothing; expireThreshold::Dates.Period=Dates.Minute(5)) =
    AWSCredentials("", access_key_id, secret_access_key, session_token, expiration, expireThreshold)

# Return the credential fields, reloading credentials that expire within `expireThreshold`.
# Concurrent callers share one reload. If it fails or finds nothing, unexpired credentials
# stay in use and the next call tries again; expired ones raise its error.
function getCredentials(x::AWSCredentials)
    return withreloadlock(x.lock) do fresh
        if expired(x)
            try
                reload!(x.lock, fresh) do
                    creds = awsLoadConfig!(x.profile, x.expireThreshold)
                    isempty(creds.access_key_id) &&
                        error("AWS credentials expired at $(x.expiration) UTC and could not be reloaded")
                    x.access_key_id = creds.access_key_id
                    x.secret_access_key = creds.secret_access_key
                    x.session_token = creds.session_token
                    x.expiration = creds.expiration
                end
            catch err
                (err isa InterruptException || Dates.now(Dates.UTC) >= x.expiration) && rethrow()
            end
        end
        return (access_key_id=x.access_key_id, secret_access_key=x.secret_access_key, session_token=x.session_token)
    end
end

function AWSCredentials(profile::String="", load::Bool=true; expireThreshold=Dates.Minute(5))
    load && return awsLoadConfig!(profile, expireThreshold)
    return AWS_CONFIGS["credentials"]
end

getCredentialsFile() = get(AWS_CONFIGS, "aws_shared_credentials_file", joinpath(homedir(), ".aws", "credentials"))
getConfigFile() = get(AWS_CONFIGS, "aws_config_file", joinpath(homedir(), ".aws", "config"))

"""
    awsLoadConfig!(profile="", expireThreshold=Minute(5)) -> AWSCredentials

Load credentials the way the AWS SDKs do: the first provider that has credentials supplies
all of them. Providers in order: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`; web identity from
`AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`; the profile (credentials file `[name]`, config
file `[profile name]`, with `role_arn` resolved through STS); the ECS container endpoint, which
is final when configured; EC2 instance metadata. A nonempty `profile` names the profile and
skips the two environment providers; otherwise `AWS_PROFILE` or `default` is used. The result
is also stored as `AWS_CONFIGS["credentials"]`.
"""
function awsLoadConfig!(profile::String="", expireThreshold=Dates.Minute(5))
    Base.@lock AWS_LOAD_LOCK begin
        foreach(key -> delete!(AWS_CONFIGS, key), AWS_PROFILE_KEYS)
        Figgy.load!(AWS_CONFIGS, alternateConfigFileLocations(), awsProfileProgramArgument())
        credFile = getCredentialsFile()
        configFile = getConfigFile()
        name = isempty(profile) ? get(AWS_CONFIGS, "profile", "default") : profile
        settings = awsProfileSettings(name, credFile, configFile)
        # Settings such as `region` keep their precedence: arguments, environment, profile.
        Figgy.load!(AWS_CONFIGS, awsProgramArguments(), awsConfigEnvironmentVariables(), settings)
        foreach(key -> delete!(AWS_CONFIGS, key), ("aws_access_key_id", "aws_secret_access_key", "aws_session_token"))
        creds = awsResolveCredentials(settings, isempty(profile), credFile, configFile)
        credentials = creds === nothing ? AWSCredentials(profile, "", "", "", nothing, expireThreshold) :
            AWSCredentials(profile, creds.access_key_id, creds.secret_access_key, creds.session_token, creds.expiration, expireThreshold)
        Figgy.load!(AWS_CONFIGS, "credentials" => credentials)
        return credentials
    end
end

function awsResolveCredentials(settings, chain::Bool, credFile, configFile)
    if chain
        env = Dict{String,String}(awsConfigEnvironmentVariables())
        creds = awsStaticCredentials(env)
        creds === nothing || return creds
        haskey(env, "role_arn") && haskey(env, "web_identity_token_file") && return awsWebIdentity(env)
    end
    creds = awsProfileCredentials(settings, credFile, configFile)
    creds === nothing || return creds
    # A configured container endpoint is final: never fall back to the host's role.
    isempty(get(ENV, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")) || return awsSourceCredentials(ECSCredentialsSource())
    return awsSourceCredentials(EC2CredentialsSource())
end

# Profile `name` from the credentials file section `[name]` and the config file section
# `[profile name]` (`[default]` for the default profile). The credentials file wins.
function awsProfileSettings(name, credFile, configFile)
    settings = Dict{String,String}()
    section = name == "default" ? name : "profile $name"
    for source in (Figgy.IniFile(credFile, name), Figgy.IniFile(configFile, section))
        for (key, value) in Figgy.load(source)
            get!(settings, key, value)
        end
    end
    return settings
end

function awsStaticCredentials(settings)
    key = get(settings, "aws_access_key_id", "")
    secret = get(settings, "aws_secret_access_key", "")
    (isempty(key) || isempty(secret)) && return nothing
    expiration = get(settings, "expiration", nothing)
    return (access_key_id=String(key), secret_access_key=String(secret),
        session_token=String(get(settings, "aws_session_token", "")),
        expiration=expiration === nothing ? nothing : DateTime(rstrip(expiration, 'Z')))
end

function awsSourceCredentials(source)
    settings = Dict{String,Any}(Figgy.load(source))
    region = get(settings, "region", nothing)
    region === nothing || haskey(AWS_CONFIGS, "region") || Figgy.load!(AWS_CONFIGS, "region" => region)
    return awsStaticCredentials(settings)
end

alternateConfigFileLocations() = Figgy.kmap(Figgy.EnvironmentVariables(),
    "AWS_CONFIG_FILE" => "aws_config_file",
    "AWS_SHARED_CREDENTIALS_FILE" => "aws_shared_credentials_file",
    "AWS_PROFILE" => "profile"; select=true
)

awsProfileProgramArgument() = Figgy.select(Figgy.ProgramArguments(), "profile")

awsConfigEnvironmentVariables() = Figgy.kmap(Figgy.EnvironmentVariables(),
    "AWS_ACCESS_KEY_ID" => "aws_access_key_id",
    "AWS_SECRET_ACCESS_KEY" => "aws_secret_access_key",
    "AWS_SESSION_TOKEN" => "aws_session_token",
    "AWS_CA_BUNDLE" => "ca_bundle",
    "AWS_MAX_ATTEMPTS" => "max_attempts",
    "AWS_DEFAULT_OUTPUT" => "output",
    "AWS_REGION" => "region",
    "AWS_DEFAULT_REGION" => "default_region",
    "AWS_RETRY_MODE" => "retry_mode",
    "AWS_ROLE_ARN" => "role_arn",
    "AWS_ROLE_SESSION_NAME" => "role_session_name",
    "AWS_WEB_IDENTITY_TOKEN_FILE" => "web_identity_token_file"; select=true
)

awsProgramArguments() = Figgy.kmap(Figgy.ProgramArguments(),
    "ca-bundle" => "ca_bundle",
    "output" => "output",
    "region" => "region"; select=true
)

# Metadata endpoints: no proxy or redirects. Instance metadata also gets a short connect
# timeout and no retries, as in the AWS SDKs.
const METADATA_KW = (proxy=nothing, redirect=false)
const IMDS_KW = (METADATA_KW..., connect_timeout=1, request_timeout=5, retry=false)

# from within an ECS container, there's a specific endpoint setup to retrieve credentials
struct ECSCredentialsSource <: Figgy.FigSource
    ecsHost::String # for testing purposes
end
ECSCredentialsSource() = ECSCredentialsSource("http://169.254.170.2")

function Figgy.load(x::ECSCredentialsSource)
    url = get(ENV, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
    isempty(url) && return ()
    try
        # RoleArn identifies the role for these already-vended credentials. It is not
        # a request to assume the role again through STS.
        return Figgy.kmap(Figgy.JsonObject(HTTP.get("$(x.ecsHost)$url"; METADATA_KW...).body),
            "AccessKeyId" => "aws_access_key_id",
            "SecretAccessKey" => "aws_secret_access_key",
            "Token" => "aws_session_token",
            "Expiration" => "expiration",
        )
    catch
        return ()
    end
end
reloadECSCredentials!(ecsHost=nothing) = Figgy.load!(AWS_CONFIGS, ECSCredentialsSource(ecsHost))

# similar to ECS, EC2 instances can be configured to have credentials provided automatically
struct EC2CredentialsSource <: Figgy.FigSource
    ec2Host::String # for testing purposes
    port::Int # for testing purposes
end
EC2CredentialsSource() = EC2CredentialsSource("169.254.169.254", 80)

function Figgy.load(x::EC2CredentialsSource)
    base = "http://$(x.ec2Host):$(x.port)/latest"
    # IMDSv2 session token. Instances that allow IMDSv1 also answer without one.
    headers = try
        resp = HTTP.put("$base/api/token", ["X-aws-ec2-metadata-token-ttl-seconds" => "21600"]; status_exception=false, IMDS_KW...)
        resp.status == 200 ? ["X-aws-ec2-metadata-token" => String(resp.body)] : Pair{String,String}[]
    catch err
        err isa InterruptException && rethrow()
        Pair{String,String}[]
    end
    try
        imds(path) = String(HTTP.get("$base/meta-data/$path", headers; IMDS_KW...).body)
        role = strip(imds("iam/security-credentials/"))
        region = imds("placement/region")
        # The metadata service has already assumed the instance role and returned its
        # temporary credentials. Do not treat response metadata as role configuration.
        creds = Figgy.kmap(Figgy.JsonObject(imds("iam/security-credentials/$role")),
            "AccessKeyId" => "aws_access_key_id",
            "SecretAccessKey" => "aws_secret_access_key",
            "Token" => "aws_session_token",
            "Expiration" => "expiration",
        )
        return push!(collect(Pair{String,Any}, creds), "region" => region)
    catch
        return ()
    end
end
reloadEC2Credentials!(ecsHost="169.254.169.254", port=80) = Figgy.load!(AWS_CONFIGS, EC2CredentialsSource(ecsHost, port))

# STS request parameters are Any-valued: DurationSeconds is an Int and WebIdentityToken
# is read from a file, neither of which fits a Dict{String,String}
sts_params(roleArn) = Dict{String,Any}("RoleArn" => roleArn)

stsURL() = get(ENV, "AWS_ENDPOINT_URL_STS", "https://sts.amazonaws.com/")

function awsProfileCredentials(settings, credFile, configFile)
    haskey(settings, "role_arn") || return awsStaticCredentials(settings)
    source = if haskey(settings, "source_profile")
        awsStaticCredentials(awsProfileSettings(settings["source_profile"], credFile, configFile))
    elseif haskey(settings, "credential_source")
        awsCredentialSource(settings["credential_source"])
    elseif haskey(settings, "web_identity_token_file")
        return awsWebIdentity(settings)
    else
        throw(ArgumentError("AWS profile with role_arn needs source_profile, credential_source, or web_identity_token_file"))
    end
    source === nothing && throw(ArgumentError("no source credentials for AWS role $(settings["role_arn"])"))
    params = awsRoleParams(settings)
    haskey(settings, "external_id") && (params["ExternalId"] = settings["external_id"])
    #TODO: support mfa_serial by prompting user for OTP: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-configure-role-mfa
    return awsAssumeRole("AssumeRole", params,
        AWSCredentials(source.access_key_id, source.secret_access_key, source.session_token))
end

function awsCredentialSource(name)
    name == "Environment" && return awsStaticCredentials(Dict{String,String}(awsConfigEnvironmentVariables()))
    name == "EcsContainer" && return awsSourceCredentials(ECSCredentialsSource())
    name == "Ec2InstanceMetadata" && return awsSourceCredentials(EC2CredentialsSource())
    throw(ArgumentError("unsupported AWS credential_source `$name`"))
end

function awsRoleParams(settings)
    params = sts_params(settings["role_arn"])
    params["RoleSessionName"] = get(settings, "role_session_name") do
        "CloudBase.jl-RSN-$(Dates.format(now(UTC), ISO8601))-$(time_ns())"
    end
    if haskey(settings, "duration_seconds")
        dur = parse(Int, settings["duration_seconds"])
        (900 <= dur <= 43200) || throw(ArgumentError("invalid duration_seconds configuration, must be 900 <= duration_seconds <= 43200: $dur"))
        params["DurationSeconds"] = dur
    end
    return params
end

function awsWebIdentity(settings)
    params = awsRoleParams(settings)
    # the token is sent as a request parameter, so it must be text, not raw bytes
    params["WebIdentityToken"] = strip(read(settings["web_identity_token_file"], String))
    return awsAssumeRole("AssumeRoleWithWebIdentity", params, nothing)
end

function awsAssumeRole(action, params, credentials)
    params["Action"] = action
    params["Version"] = "2011-06-15"
    # The global endpoint signs for us-east-1; a regional STS host signs for its own region.
    resp = AWS.post(stsURL(), [], params; credentials, service="sts", region=AWS_DEFAULT_REGION)
    creds = Figgy.XmlObject(resp.body, "$(action)Result.Credentials").figs
    return (access_key_id=String(creds["AccessKeyId"]), secret_access_key=String(creds["SecretAccessKey"]),
        session_token=String(creds["SessionToken"]), expiration=DateTime(rstrip(creds["Expiration"], 'Z')))
end

const AWS_DEFAULT_REGION = "us-east-1"

# try to get service/region from host directly (otherwise, require user to pass service)
# or use env variables for region
# "amazonaws.com"                                          -> (nothing, nothing)
# "s3.amazonaws.com"                                       -> ("s3", nothing)
# "s3.us-west-2.amazonaws.com"                             -> ("s3", "us-west-2")
# "bucket.s3.us-west-2.amazonaws.com"                      -> ("s3", "us-west-2")
# "bucket.s3.amazonaws.com"                                -> ("s3", nothing)
# "my.dotted.bucket.s3.us-west-2.amazonaws.com"            -> ("s3", "us-west-2")
# "bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com" -> ("s3", "us-east-1")
#
# Matching is anchored at the *end* of the host rather than counting labels from the
# front: a bucket name may itself contain dots, so a fixed label count mistakes part of
# the bucket for the service (e.g. "my.bucket.s3.amazonaws.com" previously returned
# service="bucket", region="s3", producing a signature for the wrong credential scope).
function urlServiceRegion(host)
    spl = split(lowercase(String(host)), '.')
    suffix_length = if length(spl) >= 3 && spl[end - 1:end] == ["amazonaws", "com"]
        2
    elseif length(spl) >= 4 && spl[end - 2:end] == ["amazonaws", "com", "cn"]
        3
    else
        return (nothing, nothing)
    end
    rest = @view spl[1:(end - suffix_length)]
    isempty(rest) && return (nothing, nothing)
    if length(rest) >= 4 && rest[end] == "vpce"
        # bucket.vpce-<id>.<service>.<region>.vpce.amazonaws.com
        return (endpointSigningService(rest[end - 2]), rest[end - 1])
    end
    if length(rest) == 1
        # <service>.amazonaws.com
        return (endpointSigningService(rest[1]), nothing)
    end
    last_label = rest[end]
    # a region label looks like "us-west-2"/"eu-central-1"; a service label does not
    if isregionlabel(last_label)
        service_index = lastindex(rest) - 1
        while service_index > 1 && rest[service_index] in ("dualstack", "fips")
            service_index -= 1
        end
        return (endpointSigningService(rest[service_index]), last_label)
    end
    # no region present, so the final label is the service (anything before it is the bucket)
    return (endpointSigningService(last_label), nothing)
end

endpointSigningService(service) = replace(String(service), r"-fips$" => "")

# AWS region identifiers are <area>-<direction>-<number>, e.g. us-west-2, ap-southeast-1,
# us-gov-east-1, cn-north-1. Service labels ("s3", "sts", "dynamodb") never match this.
function isregionlabel(label)
    parts = split(label, '-')
    length(parts) >= 3 || return false
    all(isdigit, parts[end]) || return false
    return all(p -> !isempty(p) && all(c -> 'a' <= c <= 'z', p), @view parts[1:end-1])
end

# Previously `unsafe_wrap(Array, pointer(x), sizeof(x))`, which aliases the String's buffer
# without keeping it alive: callers pass temporaries (e.g. bytes("AWS4$secret")) that the
# collector is free to reclaim before the resulting array is consumed. Copy instead; signing
# is not hot enough for the alias to be worth the hazard.
bytes(x::String) = Vector{UInt8}(codeunits(x))
trimall(x) = strip(replace(x, r"[ \t]+" => " "))
canonicalHeader(x::Pair) = strip(lowercase(x.first)) => trimall(x.second)
const ISO8601 = dateformat"yyyymmdd\THHMMSS\Z"
const ISO8601DATE = dateformat"yyyymmdd"
const SIG2DF = dateformat"yyyy-mm-dd\THH:MM:SS\Z"
const SIG2DFNOZ = dateformat"yyyy-mm-dd\THH:MM:SS"

# codeunit iterator for Char
struct CodeUnits
    c::Char
end
Base.IteratorSize(::Type{CodeUnits}) = Base.SizeUnknown()
Base.iterate(c::CodeUnits, i=1) = i > ncodeunits(c.c) ? nothing :
    ((Base.bitcast(UInt32, c.c) >> (32 - i * 8) % UInt8), i + 1)

safe(c::Char) = c == '-' || c == '_' || c == '.' || c == '~' || ('A' <= c <= 'Z') || ('a' <= c <= 'z') || ('0' <= c <= '9')
uriencode(c::Char) = join((string('%', uppercase(string(Int(b), base=16, pad=2))) for b in CodeUnits(c)))
uriencode(x, path=false) = join((safe(c) || (path && c == '/')) ? c : uriencode(c) for c in x)

function canonicalQuery(url)
    encoded = [(uriencode(k), uriencode(v)) for (k, v) in queryparampairs(url)]
    sort!(encoded; by=identity)
    return join((string(k, "=", v) for (k, v) in encoded), "&")
end

function canonicalRequestHeaders(request, url)
    headers = map(canonicalHeader, request.headers)
    if !any(x -> x.first == "host", headers)
        host = if request.host !== nothing
            request.host
        elseif isempty(url.port)
            url.host
        else
            "$(url.host):$(url.port)"
        end
        push!(headers, "host" => String(host))
    end
    sort!(headers; by=x -> x.first)
    deduplicateHeaders!(headers)
    return headers
end

function deduplicateHeaders!(headers)
    isempty(headers) && return
    j = 1
    for i = 2:length(headers)
        k, v = headers[i]
        if k == headers[j].first
            headers[j] = k => string(headers[j].second, ',', v)
        else
            j += 1
            headers[j] = k => v
        end
    end
    resize!(headers, j)
    return
end

function awssign!(request::HTTP.Request, url::URI; service=nothing, region=nothing, credentials::Union{Nothing, AWSCredentials}=nothing, x_amz_date=nothing, includeContentSha256=true, debug=false, kw...)
    if debug
        return LoggingExtras.withlevel(Logging.Debug; verbosity=1) do
            awssign!(request, url; service, region, credentials, x_amz_date, includeContentSha256, kw...)
        end
    end
    # An absent credential object denotes an intentionally public request.
    credentials === nothing && return
    # determine the service & region for the request (needed for signing)
    serv, reg = urlServiceRegion(url.host)
    service = _some(service, serv)
    service === nothing && throw(ArgumentError("unable to determine AWS service for request from host `$(url.host)`; pass `service=X`"))
    region = something(reg, region, get(AWS_CONFIGS, "region", AWS_DEFAULT_REGION))
    @debugv 1 "computed service = `$service`, region = `$region` for aws request"
    # determine credentials
    creds = getCredentials(credentials)
    # we're going to set Authorization header, so delete it if present
    HTTP.removeheader(request, "Authorization")
    dt = x_amz_date === nothing ? Dates.now(Dates.UTC) : x_amz_date
    requestDateTime = Dates.format(dt, ISO8601)
    HTTP.setheader(request, "x-amz-date" => requestDateTime)
    if !isempty(creds.session_token)
        HTTP.setheader(request, "x-amz-security-token" => creds.session_token)
    end

    # https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    # Task 1: Create a canonical request for Signature Version 4
    service = lowercase(service)
    request_path = isempty(url.path) ? "/" : url.path
    canonicalURI = if service == "s3"
        # Request URLs contain an escaped path. Decode it before applying SigV4
        # encoding so `%20` is signed as `%20`, not `%2520`. Do not normalize
        # S3 paths because repeated slashes and dot segments are object-key data.
        uriencode(URIs.unescapeuri(request_path), true)
    else
        URIs.normpath(service == "service" ? uriencode(request_path, true) : escapepath(request_path))
    end
    # @show canonicalURI
    # SigV4 sorts the encoded parameter names and values, not their raw forms.
    canonicalQueryString = canonicalQuery(url)
    # @show url, queryparampairs(url), canonicalQueryString
    body = requestbodybytes(request)
    #TODO: handle streaming request bodies?
    payloadHash = bytes2hex(payloadsha256(body))
    if includeContentSha256
        HTTP.setheader(request, "x-amz-content-sha256" => payloadHash)
    end
    # Canonicalize the final header values that will be sent on the wire.
    headers = canonicalRequestHeaders(request, url)
    canonicalHeaders = join(map(x -> "$(x.first):$(x.second)", headers), "\n")
    signedHeaders = join(map(first, headers), ";")

    canonicalRequest = """$(request.method)
    $canonicalURI
    $canonicalQueryString
    $canonicalHeaders

    $signedHeaders
    $payloadHash"""
    # @show canonicalRequest
    @debugv 1 "computed canonical request = `$canonicalRequest`"
    hashedCanonicalRequest = bytes2hex(sha256(canonicalRequest))
    # Task 2: Create a string to sign for Signature Version 4
    requestDate = Dates.format(dt, ISO8601DATE)
    credentialScope = "$requestDate/$region/$service/aws4_request"
    stringToSign = """AWS4-HMAC-SHA256
    $requestDateTime
    $credentialScope
    $hashedCanonicalRequest"""
    @debugv 1 "computed string to sign = `$stringToSign`"
    # Task 3: Calculate the signature for AWS Signature Version 4
    signingKey = hmac_sha256(hmac_sha256(hmac_sha256(hmac_sha256(bytes("AWS4$(creds.secret_access_key)"), requestDate), region), service), "aws4_request")
    signature = bytes2hex(hmac_sha256(signingKey, stringToSign))
    # Task 4: Add the signature to the HTTP request
    header = "AWS4-HMAC-SHA256 Credential=$(creds.access_key_id)/$credentialScope, SignedHeaders=$signedHeaders, Signature=$signature"
    HTTP.setheader(request, "Authorization" => header)
    return
end

function awssignv2!(request::HTTP.Request, url::URI; credentials::Union{Nothing, AWSCredentials}=nothing, version=nothing, timestamp=nothing, kw...)
    credentials === nothing && return
    if request.method == "GET"
        params = queryparams(url)
    else
        request.method == "POST" || throw(ArgumentError("unsupported method for AWS SigV2 request signing `$(request.method)`"))
        params = queryparams(HTTP.URI("?" * String(copy(requestbodybytes(request)))))
    end
    # determine credentials
    creds = getCredentials(credentials)
    params["AWSAccessKeyId"] = creds.access_key_id
    params["SignatureVersion"] = "2"
    params["SignatureMethod"] = "HmacSHA256"
    if version !== nothing
        params["Version"] = version
    end
    params["Timestamp"] = Dates.format(timestamp === nothing ? Dates.now(Dates.UTC) : timestamp, SIG2DFNOZ)
    # params["Expires"] = Dates.format(now(UTC) + Dates.Minute(2), SIG2DF)
    if !isempty(creds.session_token)
        params["SecurityToken"] = creds.session_token
    end
    sorted = sort!(collect(params); by=x->x.first)
    stringToSign = """$(request.method)
    $(lowercase(url.host))
    $(isempty(url.path) ? "/" : url.path)
    $(HTTP.escapeuri(sorted))"""
    signature = strip(base64encode(hmac_sha256(bytes(creds.secret_access_key), stringToSign)))
    if request.method == "GET"
        push!(sorted, "Signature" => signature)
        request.target = (isempty(url.path) ? "/" : url.path) * "?" * HTTP.escapeuri(sorted)
    else
        params["Signature"] = signature
        # HTTP 2 parameterises Request on its body type, so the body cannot be replaced
        # in place. Return the signed form-encoded body for the caller to send.
        return HTTP.escapeuri(params)
    end
    return nothing
end

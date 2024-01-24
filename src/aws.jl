const AWS_CONFIGS = Figgy.Store()

mutable struct AWSCredentials <: CloudCredentials
    lock::ReentrantLock
    profile::String
    access_key_id::String
    secret_access_key::String
    session_token::String
    expiration::Union{Nothing, DateTime}
    expireThreshold::Dates.Period
end

AWSCredentials(profile::String, access_key_id::String, secret_access_key::String, session_token::String, expiration, expireThreshold) =
    AWSCredentials(ReentrantLock(), profile, access_key_id, secret_access_key, session_token, expiration, expireThreshold)

# manual constructor
AWSCredentials(access_key_id::String, secret_access_key::String, session_token::String="", expiration=nothing; expireThreshold::Dates.Period=Dates.Minute(5)) =
    AWSCredentials("", access_key_id, secret_access_key, session_token, expiration, expireThreshold)

# accessor method that locks, checks expiration, and refreshes if necessary, before returning
# individual credential pieces as NamedTuple; used in awssign!
function getCredentials(x::AWSCredentials)
    Base.@lock x.lock begin
        if expired(x)
            awsLoadConfig!(x.profile, x.expireThreshold)
            creds = AWS_CONFIGS["credentials"]
            # we refreshed the credentials, now we update the fields of the original creds
            x.access_key_id = creds.access_key_id
            x.secret_access_key = creds.secret_access_key
            x.session_token = creds.session_token
            x.expiration = creds.expiration
        end
        return (access_key_id=x.access_key_id, secret_access_key=x.secret_access_key, session_token=x.session_token)
    end
end

function AWSCredentials(profile::String="", load::Bool=true; expireThreshold=Dates.Minute(5))
    load && awsLoadConfig!(profile, expireThreshold)
    return AWS_CONFIGS["credentials"]
end

getCredentialsFile() = get(AWS_CONFIGS, "aws_shared_credentials_file", joinpath(homedir(), ".aws", "credentials"))
getConfigFile() = get(AWS_CONFIGS, "aws_config_file", joinpath(homedir(), ".aws", "config"))

function awsLoadConfig!(profile::String="", expireThreshold=Dates.Minute(5))
    # on each fresh load, we want to clear out potentially stale credential fields
    # note that each load, we *will* replace AWS_CONFIGS["credentials"]
    # so we still keep track of their history bundled together
    delete!(AWS_CONFIGS, "aws_access_key_id")
    delete!(AWS_CONFIGS, "aws_secret_access_key")
    delete!(AWS_CONFIGS, "aws_session_token")
    delete!(AWS_CONFIGS, "expiration")
    # first we load alternative config file locations & profile
    # in case we should use those instead of defaults
    Figgy.load!(AWS_CONFIGS, alternateConfigFileLocations(), awsProfileProgramArgument())
    # now we do our full load
    credFile = getCredentialsFile()
    configFile = getConfigFile()
    profile = !isempty(profile) ? profile : get(AWS_CONFIGS, "profile", "default")
    if profile != "default"
        profile = "profile $profile"
    end
    Figgy.load!(AWS_CONFIGS,
        awsProgramArguments(),
        awsConfigEnvironmentVariables(),
        Figgy.IniFile(credFile, profile),
        Figgy.IniFile(configFile, profile),
        ECSCredentialsSource(),
        EC2CredentialsSource(),
    )
    if haskey(AWS_CONFIGS, "role_arn")
        # if we have a role_arn, we need to call STS to get temporary credentials
        loadRoleArn(AWS_CONFIGS["role_arn"], credFile, configFile)
    end
    # after doing a single config "load", we want to bundle the credentials
    # together as one object in AWS_CONFIGS, so we know they all came "together"
    exp = get(AWS_CONFIGS, "expiration", nothing)
    expiration = exp === nothing ? exp : DateTime(rstrip(exp, 'Z'))
    Figgy.load!(AWS_CONFIGS, "credentials" =>
        AWSCredentials(profile,
            get(AWS_CONFIGS, "aws_access_key_id", ""),
            get(AWS_CONFIGS, "aws_secret_access_key", ""),
            get(AWS_CONFIGS, "aws_session_token", ""),
            expiration, expireThreshold
        )
    )
    return
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

# from within an ECS container, there's a specific endpoint setup to retrieve credentials
struct ECSCredentialsSource <: Figgy.FigSource
    ecsHost::String # for testing purposes
end
ECSCredentialsSource() = ECSCredentialsSource("http://169.254.170.2")

function Figgy.load(x::ECSCredentialsSource)
    host = x.ecsHost
    # check if we have necessary config to fetch ECS creds
    Figgy.load!(AWS_CONFIGS, Figgy.kmap(Figgy.EnvironmentVariables(),
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" => "container_credentials_relative_uri"; select=true
    ))
    url = get(AWS_CONFIGS, "container_credentials_relative_uri", "")
    isempty(url) && return ()
    try
        return Figgy.kmap(Figgy.JsonObject(HTTP.get("$host$url").body),
            "AccessKeyId" => "aws_access_key_id",
            "SecretAccessKey" => "aws_secret_access_key",
            "Token" => "aws_session_token",
            "Expiration" => "expiration",
            "RoleArn" => "role_arn",
        )
    catch
        return ()
    end
end
reloadECSCredentials!(ecsHost=nothing) = Figgy.load!(AWS_CONFIGS, ECSCredentialsSource(ecsHost))

# similar to ECS, EC2 instances can be configured to have credentials provided automatically
# note that in awsLoadConfig, ECS takes precedence over EC2 as AWS dictates the precedence
struct EC2CredentialsSource <: Figgy.FigSource
    ec2Host::String # for testing purposes
    port::Int # for testing purposes
end
EC2CredentialsSource() = EC2CredentialsSource("169.254.169.254", 80)

function Figgy.load(x::EC2CredentialsSource)
    host = x.ec2Host
    port = x.port
    # check if we have necessary config to fetch EC2 creds
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/identify_ec2_instances.html
    canconnect(host, port) || return ()
    try
        role = String(HTTP.get("http://$host:$port/latest/meta-data/iam/security-credentials/").body)
        region = String(HTTP.get("http://$host:$port/latest/meta-data/placement/region").body)
        Figgy.load!(AWS_CONFIGS, "region" => region)
        return Figgy.kmap(Figgy.JsonObject(HTTP.get("http://$host:$port/latest/meta-data/iam/security-credentials/$role").body),
            "AccessKeyId" => "aws_access_key_id",
            "SecretAccessKey" => "aws_secret_access_key",
            "Token" => "aws_session_token",
            "Expiration" => "expiration",
            "RoleArn" => "role_arn",
        )
    catch
        return ()
    end
end
reloadEC2Credentials!(ecsHost="169.254.169.254", port=80) = Figgy.load!(AWS_CONFIGS, EC2CredentialsSource(ecsHost, port))

function loadRoleArn(roleArn, credFile, configFile)
    # with role_arn, we're going to call STS for temporary creds
    # so we need to figure out where our source creds come from
    params = Dict("RoleArn" => roleArn)
    if haskey(AWS_CONFIGS, "role_session_name")
        params["RoleSessionName"] = AWS_CONFIGS["role_session_name"]
    else
        params["RoleSessionName"] = "CloudBase.jl-RSN-$(Dates.format(now(UTC), ISO8601))-$(time_ns())"
    end
    sprofile = get(AWS_CONFIGS, "source_profile", "")
    params["Action"] = "AssumeRole"
    params["Version"] = "2011-06-15"
    if sprofile != ""
        # source_profile is the config file profile we should use for creds to call STS
        Figgy.load!(AWS_CONFIGS, Figgy.IniFile(credFile, sprofile), Figgy.IniFile(configFile, sprofile))
        credentials = AWSCredentials(
            get(AWS_CONFIGS, "aws_access_key_id", ""),
            get(AWS_CONFIGS, "aws_secret_access_key", ""),
            get(AWS_CONFIGS, "aws_session_token", "")
        )
    elseif haskey(AWS_CONFIGS, "credential_source")
        # if credential_source is provided, we've already loaded source creds
        # above via environment variables, ecs, or ec2, so we should be ready to call STS
        credentials = AWSCredentials(
            get(AWS_CONFIGS, "aws_access_key_id", ""),
            get(AWS_CONFIGS, "aws_secret_access_key", ""),
            get(AWS_CONFIGS, "aws_session_token", "")
        )
    elseif haskey(AWS_CONFIGS, "web_identity_token_file")
        # load the web identity token to be passed to STS
        params["WebIdentityToken"] = read(AWS_CONFIGS["web_identity_token_file"])
        params["Action"] = "AssumeRoleWithWebIdentity"
        credentials = nothing
    end
    if haskey(AWS_CONFIGS, "duration_seconds")
        dur = parse(Int, AWS_CONFIGS["duration_seconds"])
        (900 <= dur <= 43200) || throw(ArgumentError("invalid duration_seconds configuration, must be 900 <= duration_seconds <= 43200: $dur"))
        params["DurationSeconds"] = dur
    end
    if haskey(AWS_CONFIGS, "external_id")
        params["ExternalId"] = AWS_CONFIGS["external_id"]
    end
    #TODO: support mfa_serial by prompting user for OTP: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-configure-role-mfa
    #TODO: support region-specific STS?
    resp = AWS.post("https://sts.amazonaws.com/", [], params; credentials)
    # parse xml results, load into AWS_CONFIGS
    Figgy.load!(AWS_CONFIGS, Figgy.kmap(Figgy.XmlObject(resp.body, "AssumeRoleResult.Credentials"),
        "AccessKeyId" => "aws_access_key_id",
        "SecretAccessKey" => "aws_secret_access_key",
        "SessionToken" => "aws_session_token",
        "Expiration" => "expiration",
    ))
end

const AWS_DEFAULT_REGION = "us-east-1"

# try to get service/region from host directly (otherwise, require user to pass service)
# or use env variables for region
# "amazonaws.com"
# "s3.amazonaws.com"
# "s3.us-west-2.amazonaws.com"
# "bucket.s3.us-west-2.amazonaws.com"
# "bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com"
function urlServiceRegion(host)
    spl = split(host, '.')
    if length(spl) == 5 && !all(isdigit, spl[2]) && !all(isdigit, spl[3])
        return (spl[2], spl[3])
    elseif length(spl) == 4 && !all(isdigit, spl[1]) && !all(isdigit, spl[2])
        # got service & region
        return (spl[1], spl[2])
    elseif length(spl) == 3 && !all(isdigit, spl[1])
        # just got service
        return (spl[1], nothing)
    elseif length(spl) == 7 && spl[5] == "vpce" && spl[6] == "amazonaws" && spl[7] == "com"
        # See virtual private cloud https://docs.aws.amazon.com/AmazonS3/latest/userguide/privatelink-interface-endpoints.html
        # got service & region
        return (spl[3], spl[4])
    else
        # no service, no region
        return (nothing, nothing)
    end
end

bytes(x::String) = unsafe_wrap(Array, pointer(x), sizeof(x))
trimall(x) = strip(replace(x, r"[ ]{2,}" => " "))
canonicalHeader(x::HTTP.Header) = strip(lowercase(x.first)) => trimall(x.second)
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

function deduplicateHeaders!(headers)
    j = 1
    k, v = first(headers)
    for i = 2:length(headers)
        k2, v2 = headers[i]
        if k == k2
            v = "$v,$v2"
            headers[j] = k => v
            headers[i] = k => ""
        else
            k, v = k2, v2
            j = i
        end
    end
    filter!(x -> x.second != "", headers)
    return
end

function awssign!(request::HTTP.Request; service=nothing, region=nothing, credentials::Union{Nothing, AWSCredentials}=nothing, x_amz_date=nothing, includeContentSha256=true, debug=false, kw...)
    if debug
        return LoggingExtras.withlevel(Logging.Debug; verbosity=1) do
            awssign!(request; service, region, access_key_id, secret_access_key, session_token, x_amz_date, includeContentSha256, kw...)
        end
    end
    # determine the service & region for the request (needed for signing)
    serv, reg = urlServiceRegion(request.url.host)
    service = _some(service, serv)
    service === nothing && ArgumentError("unable to determine AWS service for request; pass `service=X`")
    region = something(reg, region, get(AWS_CONFIGS, "region", AWS_DEFAULT_REGION))
    @debugv 1 "computed service = `$service`, region = `$region` for aws request"
    # if the credentials is empty, let's assume this is for a public request, so no signing required
    credentials === nothing && return
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
    canonicalURI = URIs.normpath((service == "s3" || service == "service") ? uriencode(request.url.path, true) : escapepath(request.url.path))
    # @show canonicalURI
    canonicalQueryString = join((string(uriencode(k), "=", uriencode(v)) for (k, v) in sort!(queryparampairs(request.url); by=x->"$(x[1])$(x[2])")), "&")
    # @show request.url, queryparampairs(request.url), canonicalQueryString
    headers = sort!(map(canonicalHeader, request.headers); by=x->x.first)
    deduplicateHeaders!(headers)
    # @show headers
    canonicalHeaders = join(map(x -> "$(x.first):$(x.second)", headers), "\n")
    signedHeaders = join(map(first, headers), ";")
    @assert HTTP.isbytes(request.body) || request.body isa Union{Dict, NamedTuple}
    body = HTTP.isbytes(request.body) ? request.body : HTTP.escapeuri(request.body)
    #TODO: handle streaming request bodies?
    payloadHash = bytes2hex(sha256(body))
    if includeContentSha256
        HTTP.setheader(request, "x-amz-content-sha256" => payloadHash)
    end

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

function awssignv2!(request::HTTP.Request; credentials::Union{Nothing, AWSCredentials}=nothing, version=nothing, timestamp=nothing, kw...)
    credentials === nothing && return
    if request.method == "GET"
        params = queryparams(request.url)
    else
        request.method == "POST" || throw(ArgumentError("unsupported method for AWS SigV2 request signing `$(request.method)`"))
        request.body isa Dict || request.body isa NamedTuple || throw(ArgumentError("AWS SigV2 POST request signing requires a Dict or NamedTuple request body"))
        params = Dict(string(k) => v for (k, v) in pairs(request.body))
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
    $(lowercase(request.url.host))
    $(isempty(request.url.path) ? "/" : request.url.path)
    $(HTTP.escapeuri(sorted))"""
    signature = strip(base64encode(hmac_sha256(bytes(creds.secret_access_key), stringToSign)))
    if request.method == "GET"
        push!(sorted, "Signature" => signature)
        request.target = request.url.path * "?" * HTTP.escapeuri(sorted)
    else
        params["Signature"] = signature
        request.body = params
    end
    return
end

struct AzureIdentityError <: Exception
    message::String
end

Base.showerror(io::IO, err::AzureIdentityError) = print(io, err.message)

struct AzureWorkloadIdentity
    tenant_id::String
    client_id::String
    token_file::String
    authority_host::String
end

struct AzureManagedIdentity
    client_id::String
    endpoint::String
end

mutable struct AzureIdentityCredentials{S} <: CloudCredentials
    lock::ReentrantLock
    source::S
    resource::String
    auth::AccessToken
    expiration::Union{Nothing,DateTime}
    expireThreshold::Dates.Millisecond
end

function Base.show(io::IO, credentials::AzureIdentityCredentials)
    print(io, "AzureIdentityCredentials(resource=", repr(credentials.resource), ", token=****)")
    return nothing
end

function AzureIdentityCredentials(source, resource::AbstractString, expireThreshold::Dates.Period)
    uri = URI(resource)
    (uri.scheme in ("https", "api") && !isempty(uri.host) && isempty(uri.userinfo) && isempty(uri.query) && isempty(uri.fragment)) ||
        throw(ArgumentError("Azure resource must be an https:// or api:// URI"))
    threshold = convert(Dates.Millisecond, expireThreshold)
    threshold >= Dates.Millisecond(0) || throw(ArgumentError("expireThreshold must be nonnegative"))
    return AzureIdentityCredentials(ReentrantLock(), source, String(resource), AccessToken(""), nothing, threshold)
end

function AzureWorkloadIdentityCredentials(; resource::AbstractString,
        tenant_id::AbstractString=get(ENV, "AZURE_TENANT_ID", ""),
        client_id::AbstractString=get(ENV, "AZURE_CLIENT_ID", ""),
        token_file::AbstractString=get(ENV, "AZURE_FEDERATED_TOKEN_FILE", ""),
        authority_host::AbstractString=get(ENV, "AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com/"),
        expireThreshold::Dates.Period=Dates.Minute(5))
    occursin(r"^[A-Za-z0-9][A-Za-z0-9.-]*$", tenant_id) || throw(ArgumentError("Azure workload identity requires a tenant ID"))
    isempty(strip(client_id)) && throw(ArgumentError("Azure workload identity requires a client ID"))
    isempty(strip(token_file)) && throw(ArgumentError("Azure workload identity requires a federated token file"))
    authority = URI(authority_host)
    (authority.scheme == "https" && !isempty(authority.host) && isempty(authority.userinfo) &&
        authority.path in ("", "/") && isempty(authority.query) && isempty(authority.fragment)) ||
        throw(ArgumentError("Azure authority host must be an HTTPS origin"))
    source = AzureWorkloadIdentity(String(tenant_id), String(client_id), String(token_file), rstrip(String(authority_host), '/'))
    return AzureIdentityCredentials(source, resource, expireThreshold)
end

function AzureManagedIdentityCredentials(; resource::AbstractString,
        client_id::AbstractString=get(ENV, "AZURE_CLIENT_ID", ""),
        endpoint::AbstractString="http://169.254.169.254/metadata/identity/oauth2/token",
        expireThreshold::Dates.Period=Dates.Minute(5))
    uri = URI(endpoint)
    (uri.scheme == "http" && uri.host in ("169.254.169.254", "127.0.0.1", "[::1]") &&
        isempty(uri.userinfo) && isempty(uri.query) && isempty(uri.fragment)) ||
        throw(ArgumentError("Azure IMDS endpoint must use a link-local or loopback HTTP address"))
    return AzureIdentityCredentials(AzureManagedIdentity(String(client_id), String(endpoint)), resource, expireThreshold)
end

function azureIdentityRequest(method, url, headers, body=""; retry_imds=false, pause=sleep,
        connect_timeout=5, request_timeout=30, kw...)
    delays = retry_imds && method == "GET" ? (2, 6, 14, 30, 60) : ()
    response = nothing
    for attempt in 1:(length(delays) + 1)
        response = try
            HTTP.request(method, url, headers, body; status_exception=false, redirect=false, retry=false,
                connect_timeout, request_timeout, require_ssl_verification=true, kw...)
        catch err
            err isa InterruptException && rethrow()
            nothing
        end
        retryable = response === nothing || response.status in (404, 410, 429) || 500 <= response.status < 600
        (attempt > length(delays) || !retryable) && break
        pause(delays[attempt])
    end
    response === nothing && throw(AzureIdentityError("Azure identity token request failed during transport or TLS verification"))
    200 <= response.status < 300 || throw(AzureIdentityError("Azure identity token request failed (HTTP $(response.status))"))
    return response
end

function azureIdentityPayload(response)
    payload = try
        JSON.parse(String(response.body))
    catch
        nothing
    end
    payload === nothing && throw(AzureIdentityError("Azure identity endpoint returned invalid JSON"))
    payload isa AbstractDict || throw(AzureIdentityError("Azure identity endpoint did not return a JSON object"))
    return payload
end

function azureIdentitySeconds(payload, field)
    value = get(payload, field, nothing)
    seconds = value isa Real ? Float64(value) : value isa AbstractString ? tryparse(Float64, value) : nothing
    (seconds !== nothing && !(value isa Bool) && isfinite(seconds) && 0 < seconds < 1e12) ||
        throw(AzureIdentityError("Azure identity endpoint returned an invalid $field"))
    return seconds
end

function azureIdentityToken(payload)
    token = get(payload, "access_token", nothing)
    (token isa AbstractString && !isempty(strip(token)) && !occursin('\0', token)) ||
        throw(AzureIdentityError("Azure identity endpoint returned an invalid access_token"))
    token_type = get(payload, "token_type", nothing)
    (token_type isa AbstractString && lowercase(token_type) == "bearer") ||
        throw(AzureIdentityError("Azure identity endpoint did not return a Bearer token"))
    return AccessToken(String(token))
end

function azureIdentityToken(source::AzureWorkloadIdentity, resource; request=azureIdentityRequest)
    assertion = try
        strip(read(source.token_file, String))
    catch err
        err isa InterruptException && rethrow()
        nothing
    end
    assertion === nothing && throw(AzureIdentityError("Azure workload identity could not read the federated token file"))
    isempty(assertion) && throw(AzureIdentityError("Azure workload identity federated token file is empty"))
    body = HTTP.escapeuri(Dict(
        "client_id" => source.client_id,
        "scope" => resource * "/.default",
        "grant_type" => "client_credentials",
        "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion" => assertion,
    ))
    issued_at = Dates.now(Dates.UTC)
    response = request("POST", "$(source.authority_host)/$(source.tenant_id)/oauth2/v2.0/token",
        ["Content-Type" => "application/x-www-form-urlencoded"], body)
    payload = azureIdentityPayload(response)
    expiration = issued_at + Dates.Millisecond(round(Int, 1000 * azureIdentitySeconds(payload, "expires_in")))
    return azureIdentityToken(payload), expiration
end

function azureIdentityToken(source::AzureManagedIdentity, resource; request=azureIdentityRequest)
    query = Dict("api-version" => "2018-02-01", "resource" => resource)
    isempty(source.client_id) || (query["client_id"] = source.client_id)
    response = request("GET", source.endpoint, ["Metadata" => "true"]; query, proxy=nothing, retry_imds=true)
    payload = azureIdentityPayload(response)
    expiration = Dates.unix2datetime(azureIdentitySeconds(payload, "expires_on"))
    return azureIdentityToken(payload), expiration
end

function getCredentials(credentials::AzureIdentityCredentials; request=azureIdentityRequest)
    Base.@lock credentials.lock begin
        if credentials.expiration === nothing || Dates.now(Dates.UTC) >= credentials.expiration - credentials.expireThreshold
            auth, expiration = azureIdentityToken(credentials.source, credentials.resource; request)
            expiration > Dates.now(Dates.UTC) + credentials.expireThreshold ||
                throw(AzureIdentityError("Azure identity token expires before the refresh margin"))
            credentials.auth = auth
            credentials.expiration = expiration
        end
        return credentials.auth
    end
end

"""Return the cached bearer token, refreshing it before expiry. Refresh failures raise without returning a stale token."""
azureAccessToken(credentials::AzureIdentityCredentials) = getCredentials(credentials).token

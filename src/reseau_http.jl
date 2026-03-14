const HT = Reseau.HTTP
const HT_HOST_RESOLVERS = Reseau.HostResolvers
const HT_IOPOLL = Reseau.IOPoll
const HT_TLS = Reseau.TLS

mutable struct CloudPool
    limit::Int
    semaphore::Base.Semaphore
    client::HT.Client
end

function _query_string(query)::String
    query === nothing && return ""
    query isa AbstractString && return String(query)
    _is_unreserved_query_byte(b::UInt8) = (
        (b >= UInt8('A') && b <= UInt8('Z')) ||
        (b >= UInt8('a') && b <= UInt8('z')) ||
        (b >= UInt8('0') && b <= UInt8('9')) ||
        b == UInt8('-') ||
        b == UInt8('.') ||
        b == UInt8('_') ||
        b == UInt8('~')
    )
    function _percent_encode_query_component(value)::String
        text = string(value)
        encoded = IOBuffer()
        for b in codeunits(text)
            if _is_unreserved_query_byte(b)
                write(encoded, b)
            else
                print(encoded, '%')
                print(encoded, uppercase(string(b, base=16, pad=2)))
            end
        end
        return String(take!(encoded))
    end
    _pair_string(k, v) = string(_percent_encode_query_component(k), "=", _percent_encode_query_component(v))
    parts = String[]
    if query isa AbstractDict
        query_pairs = collect(pairs(query))
        sort!(query_pairs; by=x -> String(x.first))
        for (k, v) in query_pairs
            push!(parts, _pair_string(k, v))
        end
        return join(parts, "&")
    end
    if query isa AbstractVector
        for item in query
            if item isa Pair
                pair = item::Pair
                push!(parts, _pair_string(pair.first, pair.second))
                continue
            end
            if item isa Tuple && length(item) == 2
                tup = item::Tuple
                push!(parts, _pair_string(tup[1], tup[2]))
                continue
            end
            throw(ArgumentError("unsupported query entry type $(typeof(item)); expected Pair or 2-tuple"))
        end
        return join(parts, "&")
    end
    throw(ArgumentError("unsupported query type $(typeof(query)); expected String, Dict, or vector of Pair/tuples"))
end

function _append_query(url::AbstractString, query)::String
    query_s = _query_string(query)
    isempty(query_s) && return String(url)
    occursin('?', url) && return string(url, "&", query_s)
    return string(url, "?", query_s)
end

function _headers(headers=HTTP.Headers())
    headers === nothing && return HTTP.Headers()
    if headers isa AbstractDict
        return HTTP.Headers([string(k) => string(v) for (k, v) in pairs(headers)])
    end
    return HTTP.Headers(headers)
end

function _known_body_length(body)
    body isa AbstractVector{UInt8} && return length(body)
    body isa AbstractString && return ncodeunits(body)
    return nothing
end

function _prepare_form_headers!(req::HTTP.Request)
    body = req.body
    body isa Dict || body isa NamedTuple || return nothing
    HTTP.hasheader(req, "Content-Type") || HTTP.setheader(req, "Content-Type" => "application/x-www-form-urlencoded")
    HTTP.setheader(req, "Content-Length" => string(ncodeunits(HTTP.escapeuri(body))))
    return nothing
end

function _ensure_content_length!(req::HTTP.Request)
    HTTP.hasheader(req, "Content-Length") && return req
    len = _known_body_length(req.body)
    if len !== nothing
        HTTP.setheader(req, "Content-Length" => string(len))
    elseif req.method == "PUT" || req.method == "POST" || req.method == "PATCH"
        HTTP.setheader(req, "Content-Length" => "0")
    end
    return req
end

function _ensure_host_header!(req::HTTP.Request)
    HTTP.hasheader(req, "Host") && return req
    host = String(req.url.host)
    if isempty(req.url.port)
        if occursin(':', host)
            HTTP.setheader(req, "Host" => string("[", host, "]"))
        else
            HTTP.setheader(req, "Host" => host)
        end
    else
        HTTP.setheader(req, "Host" => HT_HOST_RESOLVERS.join_host_port(host, String(req.url.port)))
    end
    return req
end

function _to_http_headers(headers)::Vector{Pair{String, String}}
    pairs = Pair{String, String}[]
    sizehint!(pairs, length(headers))
    for (key, value) in headers
        key_s = key isa String ? key : String(key)
        value_s = value isa String ? value : String(value)
        push!(pairs, key_s => value_s)
    end
    return pairs
end

function _request_authority(url::HTTP.URI)::String
    host = String(url.host)
    if isempty(url.port)
        occursin(':', host) && return string("[", host, "]")
        return host
    end
    return HT_HOST_RESOLVERS.join_host_port(host, String(url.port))
end

function _request_url(req::HTTP.Request)::String
    target = isempty(req.target) ? "/" : req.target
    startswith(target, '?') && (target = string("/", target))
    return string(String(req.url.scheme), "://", _request_authority(req.url), target)
end

function _prepare_transport_body!(req::HTTP.Request)
    body = req.body
    if body isa AbstractVector{UInt8}
        return body, Int64(length(body))
    elseif body isa AbstractString
        return String(body), Int64(ncodeunits(body))
    elseif body isa IO
        bytes = read(body)
        return bytes, Int64(length(bytes))
    elseif body isa Dict || body isa NamedTuple
        form = HTTP.escapeuri(body)
        HTTP.hasheader(req, "Content-Type") || HTTP.setheader(req, "Content-Type" => "application/x-www-form-urlencoded")
        HTTP.setheader(req, "Content-Length" => string(ncodeunits(form)))
        return form, Int64(ncodeunits(form))
    elseif body === nothing
        return UInt8[], Int64(0)
    end
    throw(ArgumentError("unsupported request body type $(typeof(body))"))
end

function _filter_request_kwargs(kw)
    request_pairs = Pair{Symbol, Any}[]
    for (k, v) in pairs(kw)
        if k == :verbose || k == :canonicalize_headers || k == :logerrors || k == :observelayers
            push!(request_pairs, k => v)
        end
    end
    return (; request_pairs...)
end

function CloudPool(limit::Integer; connect_timeout::Real=0, require_ssl_verification::Bool=true)
    limit > 0 || throw(ArgumentError("pool limit must be > 0"))
    connect_timeout >= 0 || throw(ArgumentError("connect_timeout must be >= 0"))
    timeout_ns = connect_timeout == 0 ? Int64(0) : Int64(round(connect_timeout * 1.0e9))
    transport = HT.Transport(
        host_resolver=HT_HOST_RESOLVERS.HostResolver(timeout_ns=timeout_ns),
        tls_config=require_ssl_verification ? nothing : HT_TLS.Config(verify_peer=false),
        max_idle_per_host=Int(limit),
        max_idle_total=Int(limit),
        idle_timeout_ns=Int64(90_000_000_000),
    )
    client = HT.Client(transport=transport, prefer_http2=false)
    return CloudPool(Int(limit), Base.Semaphore(Int(limit)), client)
end

function Base.close(pool::CloudPool)
    close(pool.client)
    return nothing
end

function _dns_error(err)
    if err isa HT_HOST_RESOLVERS.DNSOpError
        inner = err.err
        if inner isa HT_HOST_RESOLVERS.AddressError
            _looks_like_ip_endpoint(inner.addr) && return Base.IOError(inner.err, Base.Libc.EPERM)
            return Sockets.DNSError(inner.addr, Int32(-1))
        end
        addr = string(err.addr)
        _looks_like_ip_endpoint(addr) && return Base.IOError(addr, Base.Libc.EPERM)
        return Sockets.DNSError(addr, Int32(-1))
    elseif err isa HT_HOST_RESOLVERS.AddressError
        _looks_like_ip_endpoint(err.addr) && return Base.IOError(err.err, Base.Libc.EPERM)
        return Sockets.DNSError(err.addr, Int32(-1))
    end
    return nothing
end

function _looks_like_ip_endpoint(addr::AbstractString)::Bool
    occursin(r"^\d+\.\d+\.\d+\.\d+(?::\d+)?$", addr) && return true
    occursin(r"^\[[0-9a-fA-F:]+\](?::\d+)?$", addr) && return true
    occursin(r"^[0-9a-fA-F:]+(?::\d+)?$", addr) && return true
    return false
end

function _wrap_request_error(req::HTTP.Request, err)
    err isa HTTP.StatusError && return err
    err isa HTTP.RequestError && return err
    err isa HTTP.ConnectError && return err
    dnserr = _dns_error(err)
    dnserr !== nothing && return HTTP.ConnectError(string(req.url), dnserr)
    err isa Sockets.DNSError && return HTTP.ConnectError(string(req.url), err)
    err isa Base.IOError && return HTTP.ConnectError(string(req.url), err)
    return HTTP.RequestError(req, err)
end

function _record_error!(ctx::Dict{Symbol, Any}, err)
    err isa HTTP.StatusError && (ctx[:status_errors] = get(() -> 0, ctx, :status_errors) + 1)
    err isa HTTP.ConnectError && (ctx[:connect_errors] = get(() -> 0, ctx, :connect_errors) + 1)
    if err isa HTTP.RequestError
        inner = err.error
        if inner isa HT.HTTPTimeoutError || inner isa HT_IOPOLL.DeadlineExceededError
            ctx[:timeout_errors] = get(() -> 0, ctx, :timeout_errors) + 1
        elseif inner isa Base.IOError
            ctx[:io_errors] = get(() -> 0, ctx, :io_errors) + 1
        end
    end
    return nothing
end

function _response_body_and_nbytes(response, response_stream)
    if response_stream === nothing
        body = response.body
        nbytes = response.content_length >= 0 ? Int(response.content_length) : length(body)
        return body, nbytes
    end
    nbytes = response.content_length >= 0 ? Int(response.content_length) : 0
    return UInt8[], nbytes
end

function cloudrequest(
    method::AbstractString,
    url::AbstractString,
    headers=HTTP.Headers(),
    body=nothing;
    pool::Union{Nothing, CloudPool}=nothing,
    response_stream=nothing,
    status_exception::Bool=true,
    query=nothing,
    connect_timeout::Real=0,
    readtimeout::Real=0,
    require_ssl_verification::Bool=true,
    redirect::Bool=false,
    redirect_limit::Union{Nothing, Integer}=nothing,
    redirect_method=nothing,
    forwardheaders::Bool=true,
    decompress::Union{Nothing, Bool}=false,
    credentials=nothing,
    aws::Bool=false,
    awsv2::Bool=false,
    azure::Bool=false,
    gcp::Bool=false,
    protocol::Symbol=:auto,
    logexceptionalduration::Int=0,
    kw...,
)
    start = time()
    final_url = _append_query(url, query)
    req_headers = _headers(headers)
    req_body = body === nothing ? UInt8[] : body
    uri = HTTP.URI(final_url)
    target = isempty(uri.path) && isempty(uri.query) ? "/" : HTTP.resource(uri)
    req = HTTP.Request(String(method), target, req_headers, req_body; url=uri)
    awsv2 || _prepare_form_headers!(req)
    _ensure_host_header!(req)
    _ensure_content_length!(req)
    ctx = req.context
    ctx[:connect_errors] = 0
    ctx[:io_errors] = 0
    ctx[:status_errors] = 0
    ctx[:timeout_errors] = 0
    ctx[:connect_duration_ms] = 0.0
    ctx[:read_duration_ms] = 0.0
    ctx[:write_duration_ms] = 0.0
    ctx[:nbytes] = 0
    ctx[:nbytes_written] = 0
    ctx[:retryattempt] = 0
    PREREQUEST_CALLBACK[](req.method)
    if awsv2
        awssignv2!(req; credentials, kw...)
    elseif aws
        awssign!(req; credentials, kw...)
    elseif azure
        azuresign!(req; credentials, kw...)
    elseif gcp
        gcpsign!(req; credentials, kw...)
    end
    request_url = _request_url(req)
    request_body, nbytes_written = _prepare_transport_body!(req)
    ctx[:nbytes_written] = nbytes_written
    request_kwargs = _filter_request_kwargs(kw)
    failed = false
    release = pool === nothing ? nothing : () -> Base.release(pool.semaphore)
    pool === nothing || Base.acquire(pool.semaphore)
    try
        response = if pool === nothing
            HT.request(
                req.method,
                request_url,
                req.headers,
                request_body;
                status_exception=false,
                redirect=redirect,
                redirect_limit=redirect_limit,
                redirect_method=redirect_method,
                forwardheaders=forwardheaders,
                response_stream=response_stream,
                decompress=decompress,
                connect_timeout=connect_timeout,
                readtimeout=readtimeout,
                require_ssl_verification=require_ssl_verification,
                protocol=protocol,
                request_kwargs...,
            )
        else
            HT.request(
                req.method,
                request_url,
                req.headers,
                request_body;
                status_exception=false,
                redirect=redirect,
                redirect_limit=redirect_limit,
                redirect_method=redirect_method,
                forwardheaders=forwardheaders,
                response_stream=response_stream,
                decompress=decompress,
                client=pool.client,
                readtimeout=readtimeout,
                protocol=protocol,
                request_kwargs...,
            )
        end
        response_body, nbytes = _response_body_and_nbytes(response, response_stream)
        ctx[:nbytes] = nbytes
        http_response = HTTP.Response(response.status_code, _to_http_headers(response.headers), response_body; request=req)
        if status_exception && http_response.status >= 400
            err = HTTP.StatusError(http_response.status, req.method, req.target, http_response)
            _record_error!(ctx, err)
            failed = true
            throw(err)
        end
        return http_response
    catch err
        wrapped = _wrap_request_error(req, err)
        _record_error!(ctx, wrapped)
        failed = true
        throw(wrapped)
    finally
        release === nothing || release()
        dur = (time() - start) * 1000
        if logexceptionalduration > 0 && div(dur, 1000) > logexceptionalduration
            @warn "Exceptionally long cloud request:" total_duration_ms=dur method=req.method context=req.context
        end
        METRICS_CALLBACK[](
            req.method,
            failed,
            get(() -> 0, ctx, :retryattempt),
            dur,
            get(() -> 0, ctx, :nbytes_written),
            get(() -> 0, ctx, :nbytes),
            get(() -> 0, ctx, :connect_errors),
            get(() -> 0, ctx, :io_errors),
            get(() -> 0, ctx, :status_errors),
            get(() -> 0, ctx, :timeout_errors),
            get(() -> 0.0, ctx, :connect_duration_ms),
            get(() -> 0.0, ctx, :read_duration_ms),
            get(() -> 0.0, ctx, :write_duration_ms),
        )
    end
end

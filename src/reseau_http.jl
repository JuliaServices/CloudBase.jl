const HT = HTTP
const HT_TLS = HTTP.TLS

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

function _join_host_port(host::AbstractString, port)::String
    host_s = String(host)
    port_s = string(port)
    if startswith(host_s, "[") || !occursin(':', host_s)
        return string(host_s, ":", port_s)
    end
    return string("[", host_s, "]:", port_s)
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
        HTTP.setheader(req, "Host" => _join_host_port(host, String(req.url.port)))
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
    return _join_host_port(host, String(url.port))
end

function _request_address(url::HTTP.URI)::String
    host = String(url.host)
    if isempty(url.port)
        default_port = String(url.scheme) == "https" ? 443 : 80
        return _join_host_port(host, default_port)
    end
    return _join_host_port(host, String(url.port))
end

function _request_url(req::HTTP.Request)::String
    target = isempty(req.target) ? "/" : req.target
    startswith(target, '?') && (target = string("/", target))
    return string(String(req.url.scheme), "://", _request_authority(req.url), target)
end

function _append_query(uri::HTTP.URI, query)::HTTP.URI
    query_s = _query_string(query)
    isempty(query_s) && return uri
    current = String(uri.query)
    merged = isempty(current) ? query_s : string(current, "&", query_s)
    return HTTP.URI(uri; query=merged)
end

function _uri_resource(uri::HTTP.URI)::String
    path = isempty(uri.path) ? "/" : String(uri.path)
    query = String(uri.query)
    isempty(query) && return path
    return string(path, "?", query)
end

function _reseau_headers(headers=nothing)::HT.Headers
    headers === nothing && return HT.Headers()
    headers isa HT.Headers && return copy(headers)
    if headers isa AbstractDict
        return HT.Headers([string(k) => string(v) for (k, v) in pairs(headers)])
    end
    return HT.Headers(headers)
end

function _request_target(uri::HTTP.URI)::String
    return _uri_resource(uri)
end

function _prepare_reseau_request_body(body, method::AbstractString; awsv2::Bool=false)
    body === nothing && return HT.EmptyBody(), Int64(0), nothing, nothing
    if body isa AbstractVector{UInt8}
        return HT.BytesBody(body), Int64(length(body)), nothing, nothing
    elseif body isa AbstractString
        text = body isa String ? body : String(body)
        return HT.BytesBody(codeunits(text)), Int64(ncodeunits(text)), nothing, nothing
    elseif body isa IO
        bytes = read(body)
        return HT.BytesBody(bytes), Int64(length(bytes)), nothing, nothing
    elseif body isa Dict || body isa NamedTuple
        default_content_type = "application/x-www-form-urlencoded"
        if awsv2 && method == "POST"
            params = Dict{String, Any}(string(k) => v for (k, v) in pairs(body))
            return HT.BytesBody(UInt8[]), Int64(0), params, default_content_type
        end
        form = HTTP.escapeuri(body)
        return HT.BytesBody(codeunits(form)), Int64(ncodeunits(form)), nothing, default_content_type
    end
    throw(ArgumentError("unsupported request body type $(typeof(body))"))
end

function _ensure_reseau_host_header!(req::HT.Request)::HT.Request
    HT.hasheader(req.headers, "Host") && return req
    req.host === nothing || HT.setheader(req.headers, "Host", req.host::String)
    return req
end

function _ensure_reseau_content_length!(req::HT.Request)::HT.Request
    HT.hasheader(req.headers, "Content-Length") && return req
    if req.content_length >= 0
        HT.setheader(req.headers, "Content-Length", string(req.content_length))
    elseif req.method == "PUT" || req.method == "POST" || req.method == "PATCH"
        HT.setheader(req.headers, "Content-Length", "0")
    end
    return req
end

function _request_body_http_value(body::HT.AbstractBody)
    body isa HT.EmptyBody && return UInt8[]
    body isa HT.BytesBody && return body.data
    return UInt8[]
end

function _http_request_from_reseau(req::HT.Request, uri::HTTP.URI)::HTTP.Request
    return HTTP.Request(req.method, req.target, _to_http_headers(req.headers), _request_body_http_value(req.body); url=uri)
end

function _prepare_transport_body!(req::HTTP.Request)
    body = req.body
    if body isa HT.EmptyBody
        return UInt8[], Int64(0)
    elseif body isa HT.BytesBody
        return body.data, Int64(length(body.data))
    elseif body isa AbstractVector{UInt8}
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
    transport = HT.Transport(
        tls_config=require_ssl_verification ? nothing : HT_TLS.Config(verify_peer=false),
        max_idle_per_host=Int(limit),
        max_idle_total=Int(limit),
        idle_timeout_ns=Int64(90_000_000_000),
    )
    client = HT.Client(transport=transport, prefer_http2=true)
    return CloudPool(Int(limit), Base.Semaphore(Int(limit)), client)
end

function _cloud_client(require_ssl_verification::Bool)::HT.Client
    transport = HT.Transport(tls_config=require_ssl_verification ? nothing : HT_TLS.Config(verify_peer=false))
    return HT.Client(transport=transport, prefer_http2=true)
end

function Base.close(pool::CloudPool)
    close(pool.client)
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
    _ = req
    return err
end

function _record_error!(ctx::Dict{Symbol, Any}, err)
    err isa HTTP.StatusError && (ctx[:status_errors] = get(() -> 0, ctx, :status_errors) + 1)
    if err isa Sockets.DNSError
        ctx[:connect_errors] = get(() -> 0, ctx, :connect_errors) + 1
    elseif err isa HT.HTTPTimeoutError
        ctx[:timeout_errors] = get(() -> 0, ctx, :timeout_errors) + 1
    elseif err isa Base.IOError
        ctx[:io_errors] = get(() -> 0, ctx, :io_errors) + 1
    end
    return nothing
end

function _resolve_response_sink(response_stream)
    if response_stream === nothing || response_stream isa IO || response_stream isa AbstractVector{UInt8}
        return response_stream
    end
    throw(ArgumentError("unsupported response stream sink $(typeof(response_stream)); expected nothing, IO, or AbstractVector{UInt8}"))
end

function _copy_body_to_vector!(sink::AbstractVector{UInt8}, body::HT.AbstractBody)::Int64
    buf = Vector{UInt8}(undef, 64 * 1024)
    offset = 0
    while true
        n = HT.body_read!(body, buf)
        n == 0 && break
        offset + n <= length(sink) || throw(ArgumentError("response_stream buffer too small"))
        copyto!(sink, offset + 1, buf, 1, n)
        offset += n
    end
    return Int64(offset)
end

function _copy_body_to_io!(sink::IO, body::HT.AbstractBody)::Int64
    buf = Vector{UInt8}(undef, 64 * 1024)
    total = Int64(0)
    while true
        n = HT.body_read!(body, buf)
        n == 0 && break
        write(sink, view(buf, 1:n))
        total += n
    end
    return total
end

function _read_body_bytes!(body::HT.AbstractBody)::Tuple{Vector{UInt8}, Int64}
    out = UInt8[]
    buf = Vector{UInt8}(undef, 64 * 1024)
    while true
        n = HT.body_read!(body, buf)
        n == 0 && break
        append!(out, view(buf, 1:n))
    end
    return out, Int64(length(out))
end

function _consume_response_body!(response::HT.Response, response_stream)::Tuple{Any, Int64}
    sink = _resolve_response_sink(response_stream)
    body = response.body
    try
        if sink === nothing
            return _read_body_bytes!(body)
        elseif sink isa IO
            return nothing, _copy_body_to_io!(sink::IO, body)
        else
            n = _copy_body_to_vector!(sink::AbstractVector{UInt8}, body)
            if sink isa Vector{UInt8}
                return sink::Vector{UInt8}, n
            end
            return view(sink::AbstractVector{UInt8}, 1:Int(n)), n
        end
    finally
        HT.body_close!(body)
    end
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
    method_s = uppercase(String(method))
    uri = _append_query(HTTP.URI(url), query)
    target = _request_target(uri)
    address = _request_address(uri)
    authority = _request_authority(uri)
    secure = String(uri.scheme) == "https"
    server_name = String(uri.host)
    req_headers = _reseau_headers(headers)
    req_body, content_length, sigv2_body_params, default_content_type = _prepare_reseau_request_body(body, method_s; awsv2=awsv2)
    req = HT.Request(method_s, target; headers=req_headers, body=req_body, host=authority, content_length=content_length)
    if default_content_type !== nothing && !HT.hasheader(req.headers, "Content-Type")
        HT.setheader(req.headers, "Content-Type", default_content_type::String)
    end
    _ensure_reseau_host_header!(req)
    _ensure_reseau_content_length!(req)
    PREREQUEST_CALLBACK[](req.method)
    if awsv2
        uri = awssignv2!(req, uri; body_params=sigv2_body_params, credentials, kw...)
    elseif aws
        uri = awssign!(req, uri; credentials, kw...)
    elseif azure
        uri = azuresign!(req, uri; credentials, kw...)
    elseif gcp
        uri = gcpsign!(req, uri; credentials, kw...)
    end
    http_req = req
    ctx = http_req.context
    ctx[:connect_errors] = 0
    ctx[:io_errors] = 0
    ctx[:status_errors] = 0
    ctx[:timeout_errors] = 0
    ctx[:connect_duration_ms] = 0.0
    ctx[:read_duration_ms] = 0.0
    ctx[:write_duration_ms] = 0.0
    ctx[:nbytes] = 0
    ctx[:nbytes_written] = req.content_length
    ctx[:retryattempt] = 0
    readtimeout >= 0 || throw(ArgumentError("readtimeout must be >= 0"))
    connect_timeout >= 0 || throw(ArgumentError("connect_timeout must be >= 0"))
    if readtimeout > 0
        timeout_ns = Int64(round(readtimeout * 1.0e9))
        HT.set_deadline!(HT.get_request_context(req), Int64(time_ns()) + timeout_ns)
    end
    failed = false
    release = pool === nothing ? nothing : () -> Base.release(pool.semaphore)
    pool === nothing || Base.acquire(pool.semaphore)
    req_client = nothing
    owns_client = false
    try
        if pool === nothing
            req_client = _cloud_client(require_ssl_verification)
            owns_client = true
        else
            req_client = pool.client
        end
        response = HT.do!(
            req_client,
            address,
            req;
            secure=secure,
            server_name=server_name,
            protocol=protocol,
            redirect_limit=redirect ? redirect_limit : 0,
            redirect_method=redirect_method,
            forwardheaders=forwardheaders,
        )
        if decompress !== false
            encoding = HT.header(response.headers, "Content-Encoding", nothing)
            if encoding !== nothing
                throw(ArgumentError("CloudBase response_stream path does not support HTTP 2.0 body decompression yet"))
            end
        end
        final_body, nbytes = _consume_response_body!(response, response_stream)
        ctx[:nbytes] = nbytes
        response_body = response_stream === nothing ? final_body : UInt8[]
        http_response = HTTP.Response(
            response.status,
            response_body;
            headers=_to_http_headers(response.headers),
            request=http_req,
            request_url=string(uri),
            content_length=nbytes,
            proto_major=response.proto_major,
            proto_minor=response.proto_minor,
        )
        if status_exception && http_response.status >= 400
            err = HTTP.StatusError(http_response)
            _record_error!(ctx, err)
            failed = true
            throw(err)
        end
        return http_response
    catch err
        wrapped = _wrap_request_error(http_req, err)
        _record_error!(ctx, wrapped)
        failed = true
        throw(wrapped)
    finally
        if owns_client
            close(req_client)
        end
        release === nothing || release()
        dur = (time() - start) * 1000
        if logexceptionalduration > 0 && div(dur, 1000) > logexceptionalduration
            @warn "Exceptionally long cloud request:" total_duration_ms=dur method=req.method context=ctx
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

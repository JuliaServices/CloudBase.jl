module CloudTest

export TempFile, Minio, Azurite, ECS, EC2, AzureVM

import ..CloudCredentials, ..AWS, ..Azure, ..AbstractStore

const INTERPRETER = Ref{String}()

function __init__()
    try
        # When using julia from nix, set INTERPRETER, to make sure the correct
        # dynamic loader and glibc is used (e.g. in case of glibc mismatch between
        # nix build and system glibc).
        if startswith(Base.julia_cmd()[1], "/nix/") && success(`which patchelf`)
            INTERPRETER[] = strip(read(`patchelf --print-interpreter $(unsafe_string(Base.JLOptions().julia_bin))`, String))
        end
    catch
    end
    return
end

"""
    _cmd(`cmd`)

This utility function ensures that we can run binaries in commands on Linux in Nix.
Use it as a wrapper around an existing `cmd`.
## Example:
```julia
julia> run(_cmd(`ls`))
```
"""
function _cmd(tool)
    # When on system (mostly NixOS) where /lib64/ld-linux-x86-64.so.2 is not available,
    # use the ELF interpreter from the julia binary
    if Sys.islinux() && isdefined(INTERPRETER, :x)
        pushfirst!(tool.exec, INTERPRETER[])
    end
    return tool
end


"""
    CloudTest.Config

Convenience struct passed to the user-provided functions for `Minio.with`
and `Azurite.with` that holds credentials and the store object automatically
created when the services were started. Can be iterated to get the credentials
and store, like `credentials, bucket = conf`.
"""
struct Config
    credentials::CloudCredentials
    store::AbstractStore
    port::Int
    dir::String
    process
end

Base.iterate(x::Config, i=1) = i == 1 ? (x.credentials, 2) : i == 2 ? (x.store, 3) : nothing

using Sockets, Random

const FIND_OPEN_PORT_LOCK = ReentrantLock()

function findOpenPort(_)
    port, socket = Sockets.listenany(IPv4(0), rand(RandomDevice(), 10000:50000))
    close(socket)
    return Int(port)
end

function findOpenPorts(f, n)
    # hold a global lock while finding open ports so concurrent `Minio.with`
    # `Azurite.with` calls don't conflict, which isn't likely since we're
    # starting from random ports but just in case! We also want to execute `f`
    # while holding the lock, so `f` can have a chance to start minio/azurite
    # server *on* those open ports before we return, then a subsequent `with`
    # call won't find those open ports
    Base.@lock FIND_OPEN_PORT_LOCK begin
        return f(ntuple(findOpenPort, n))
    end
end

function _connect_with_timeout(host, port::Integer, timeout::Number)
    s = TCPSocket()
    # we wrap it in this way so that the current task does not become sticky
    t = fetch(Threads.@spawn(Timer(_ -> close(s), timeout)))::Timer
    try
        connect(s, host, port)
    catch e
        if isa(e, Base.IOError) && e.code == -125
            error("Could not connect to $(host) on port $(port) in $(timeout) seconds")
        else
            rethrow(e)
        end
    finally
        close(t)
    end
    return s
end

function _wait_for_port(host, port::Integer, timeout::Number)
    t0 = time()
    while time() < t0 + timeout
        try
            s = _connect_with_timeout(host, port, timeout - (time() - t0))
            close(s)
            return nothing
        catch e
            sleep(0.1)
            continue
        end
    end
    error("Could not connect to $(host) on port $(port) in $(time() - t0) seconds")
end

# helper struct to treat tempfiles as IO objects
struct TempFile <: IO
    path
    io
end
TempFile() = TempFile(mktemp()...)
Base.close(x::TempFile) = close(x.io)
Base.unsafe_write(x::TempFile, p::Ptr{UInt8}, n::UInt) = Base.unsafe_write(x.io, p, n)
Base.write(x::TempFile, y::AbstractString) = write(x.io, y)
Base.write(x::TempFile, y::Union{SubString{String}, String}) = write(x.io, y)
Base.unsafe_read(x::TempFile, p::Ptr{UInt8}, n::UInt) = Base.unsafe_read(x.path, p, n)
Base.readbytes!(s::TempFile, b::AbstractArray{UInt8}, nb=length(b)) = readbytes!(s.io, b, nb)
Base.eof(x::TempFile) = eof(x.io)
Base.bytesavailable(x::TempFile) = bytesavailable(x.io)
Base.read(x::TempFile, ::Type{UInt8}) = read(x.io, UInt8)
Base.seekstart(x::TempFile) = seekstart(x.io)
Base.rm(x::TempFile) = rm(x.path)

module Minio

using minio_jll
import ..Config, ..findOpenPorts, ...AWS, .._cmd, .._wait_for_port

"""
    Minio.with(f; dir, bucket, public, startupDelay, debug, waitForPortTimeout)

Starts a minio server on a random open port, and passes a
[`CloudTest.Config`](@ref) to `f`, which contains the credentials
that should be used for requests made, as well as an `AWS.Bucket`
that is created to help bootstrap the testing process. Supported
keyword arguments include:
  * `dir`: directory to use for the minio server, defaults to a
    temporary directory (which is deleted when the server is stopped)
  * `bucket`: name of the bucket to create, defaults to "test"
  * `public`: whether the bucket should be public, defaults to `false`
  * `startupDelay`: number of seconds to wait after starting the
    server before creating the bucket, defaults to `0.25`; this
    can be useful on slower systems to allow time for the server
    to fully startup
  * `debug`: whether to turn on minio debug logging, defaults to `false`
  * `waitForPortTimeout`: Time to wait in seconds for the TCP port of Minio to be ready for connections
"""
function with(f; dir=nothing, kw...)
    config, proc = run(; dir, kw...)
    try
        f(config)
    finally
        kill(proc)
        result = timedwait(10.0) do
            success(proc)
        end
        if result == :timed_out
            @warn "minio server process didn't exit as expected within 10 seconds"
        end
        dir === nothing && rm(config.dir; force=true, recursive=true)
    end
    return
end

publicPolicy(bucket) = """
{
"Version":"2012-10-17",
"Statement" : [
    {
        "Effect":"Allow",
        "Sid":"1",
        "Principal": "*",
        "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:PutBucketVersioning"],
        "Resource":"arn:aws:s3:::$bucket"
    },
    {
        "Effect":"Allow",
        "Sid":"1",
        "Principal": "*",
        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:GetObjectVersion", "s3:DeleteObjectVersion"],
        "Resource":"arn:aws:s3:::$bucket/*"
    }
 ]
}
"""

# use `with`, not `run`! if you `run`, it returns `conf, p`, where `p` is the server process
# note that existing the Julia process *will not* stop the server process, which can easily
# lead to "dangling" server processes. You can `kill(p)` to stop the server process manually
function run(; dir=nothing, bucket=nothing, public=false, startupDelay=0.25, debug=false, bindIP="127.0.0.1", waitForPortTimeout=30, restartAttempts=3)
    if dir === nothing
        dir = mktempdir()
    elseif !isdir(dir)
        throw(ArgumentError("provided minio directory `$dir` doesn't exist; can't run minio server"))
    end

    for attempt in 1:restartAttempts
        local p, port
        try
            p, port = findOpenPorts(2) do ports
                port, cport = ports
                cmd = _cmd(`$(minio_jll.minio()) server $dir --address $(bindIP):$(port) --console-address $(bindIP):$(cport)`)
                p = debug ? Base.run(cmd, devnull, stderr, stderr; wait=false) : Base.run(cmd; wait=false)
                # Wait for the port to be open
                _wait_for_port("127.0.0.1", port, waitForPortTimeout)
                return p, port
            end
            credentials = AWS.Credentials("minioadmin", "minioadmin")
            bkt = AWS.Bucket(something(bucket, "jl-minio-$(rand(UInt16))"); host="http://127.0.0.1:$port")
            resp = AWS.put(bkt.baseurl, []; service="s3", credentials, status_exception=false)
            while resp.status != 200
                if resp.status == 503
                    # minio server is still starting up, so wait a bit and try again
                    sleep(startupDelay)
                    resp = AWS.put(bkt.baseurl, []; service="s3", credentials, status_exception=false)
                else
                    @error resp
                    error("unable to create minio bucket `$bkt`")
                end
            end
            if public
                resp = AWS.put(bkt.baseurl * "?policy", [], publicPolicy(bkt.name); service="s3", credentials, status_exception=false)
                if resp.status != 204
                    @error resp
                    error("unable to set minio bucket `$bkt` to public")
                end
            end
            return Config(credentials, bkt, port, dir, p), p
        catch e
            if attempt < restartAttempts
                @warn "Minio attempt $attempt failed, restarting process..." exception=e
                # Kill the process if it's still running
                try
                    kill(p)
                    # Wait for process to terminate using timedwait
                    timedwait(5.0) do
                        success(p)
                    end
                catch
                    # Process might already be dead
                end
            else
                @error "Minio failed after $restartAttempts attempts"
                rethrow(e)
            end
        end
    end
end

end # module Minio

module Azurite

using NodeJS_16_jll, azurite_jll, Dates
import ..Config, ..findOpenPorts, ...Azure, .._cmd, .._wait_for_port

"""
    Azurite.with(f; dir, bucket, public, startupDelay, debug, waitForPortTimeout)

Starts an azurite server on a random open port, and passes a
[`CloudTest.Config`](@ref) to `f`, which contains the credentials
that should be used for requests made, as well as an `Azure.Container`
that is created to help bootstrap the testing process. Supported
keyword arguments include:
  * `dir`: directory to use for the minio server, defaults to a
    temporary directory (which is deleted when the server is stopped)
  * `bucket`: name of the bucket to create, defaults to "test"
  * `public`: whether the bucket should be public, defaults to `false`
  * `startupDelay`: number of seconds to wait after starting the
    server before creating the bucket, defaults to `0.25`; this
    can be useful on slower systems to allow time for the server
    to fully startup
  * `debug`: whether to turn on minio debug logging, defaults to `false`
  * `waitForPortTimeout`: Time to wait in seconds for the TCP port of Azurite to be ready for connections
"""
function with(f; dir=nothing, debug::Bool=false, debugLog::Union{Nothing, Ref{String}}=nothing, kw...)
    config, proc = run(; dir, debug, kw...)
    try
        f(config)
    catch
        if debug
            log = read(joinpath(config.dir, "debug.log"), String)
            if debugLog !== nothing
                debugLog[] = log
            else
                println("AZURITE DEBUG.LOG:\n\n", log)
            end
        end
        rethrow()
    finally
        kill(proc)
        result = timedwait(10.0) do
            success(proc)
        end
        if result == :timed_out
            @warn "azurite server process didn't exit as expected within 10 seconds"
        end
        dir === nothing && rm(config.dir; force=true, recursive=true)
    end
    return
end

publicPolicy() = """
<?xml version="1.0" encoding="utf-8"?>  
<SignedIdentifiers>  
  <SignedIdentifier>   
    <Id>$(join(rand('a':'z', 64)))</Id>  
    <AccessPolicy>  
      <Start>$(Dates.today())</Start>  
      <Expiry>$(Dates.today() + Dates.Year(1))</Expiry>  
      <Permission>rwdl</Permission>  
    </AccessPolicy>  
  </SignedIdentifier>  
</SignedIdentifiers>
"""

# use `with`, not `run`! if you `run`, it returns `conf, p`, where `p` is the server process
# note that existing the Julia process *will not* stop the server process, which can easily
# lead to "dangling" server processes. You can `kill(p)` to stop the server process manually
function run(; dir=nothing, container=nothing, public=false, startupDelay=0.5, debug=false, use_ssl=true, skipApiVersionCheck=false, waitForPortTimeout=30, restartAttempts=3)
    if dir === nothing
        dir = mktempdir()
    elseif !isdir(dir)
        throw(ArgumentError("provided azurite directory `$dir` doesn't exist; can't run azurite server"))
    end

    for attempt in 1:restartAttempts
        local p, port
        try
            p, port = findOpenPorts(3) do ports
                port, qport, tport = ports
                cmd_args = ["-l", dir, "-d", joinpath(dir, "debug.log"), "--blobPort", port, "--queuePort", qport, "--tablePort", tport, "--oauth", "basic"]
                if use_ssl
                    cert = joinpath(@__DIR__, "test.cert")
                    key = joinpath(@__DIR__, "test.key")
                    push!(cmd_args, "--cert", cert, "--key", key)
                end
                # Avoid checking whether the Azure API version is compatible with the client?
                skipApiVersionCheck && push!(cmd_args, "--skipApiVersionCheck")
                cmd = _cmd(`$(node()) $(azurite) $(cmd_args)`)
                p = debug ? Base.run(cmd, devnull, stderr, stderr; wait=false) : Base.run(cmd; wait=false)
                # Wait for the port to be open
                _wait_for_port("127.0.0.1", port, waitForPortTimeout)
                return p, port
            end
            acct = "devstoreaccount1"
            protocol = use_ssl ? "https" : "http"
            cont = Azure.Container(something(container, "jl-azurite-$(rand(UInt16))"), acct; host="$protocol://127.0.0.1:$port")
            key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
            credentials = Azure.Credentials(acct, key)
            headers = public ? ["x-ms-blob-public-access" => "container"] : []
            # Small delay to ensure the HTTP server is ready even though the TCP port is open
            sleep(startupDelay)
            resp = Azure.put("$(cont.baseurl)?restype=container", headers; credentials, status_exception=false)
            if resp.status != 201
                @error resp
                error("unable to create azurite container `$(cont.name)`")
            end
            if public
                resp = Azure.put("$(cont.baseurl)?restype=container&comp=acl", ["x-ms-blob-public-access" => "container"], publicPolicy(); credentials, status_exception=false)
                if resp.status != 200
                    @error resp
                    error("unable to set azurite container `$(cont.name)` to public")
                end
            end
            return Config(credentials, cont, port, dir, p), p
        catch e
            if attempt < restartAttempts
                @warn "Azurite attempt $attempt failed, restarting process..." exception=e
                # Kill the process if it's still running
                try
                    kill(p)
                    # Wait for process to terminate using timedwait
                    timedwait(5.0) do
                        success(p)
                    end
                catch
                    # Process might already be dead
                end
            else
                @error "Azurite failed after $max_retries attempts"
                rethrow(e)
            end
        end
    end
end

end # module Azurite

# few helper modules to simulate different credential flows for AWS/Azure
module ECS

using HTTP

const RESP = """
{
    "AccessKeyId": "minioadmin",
    "Expiration": "EXPIRATION_DATE",
    "RoleArn": "taskRoleArn",
    "SecretAccessKey": "minioadmin",
    "Token": "ECS_TOKEN"
}"""

# utility for mocking an AWS ECS task
function with(f)
    ENV["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"] = ":50396/credentials"
    server = HTTP.serve!(50396) do req
        if req.method == "GET" && req.target == "/credentials"
            return HTTP.Response(200, RESP)
        else
            return HTTP.Response(404)
        end
    end
    try
        f()
    finally
        delete!(ENV, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        close(server)
    end
end

end # module ECS

module EC2

using HTTP

const RESP = """
{
    "AccessKeyId": "minioadmin",
    "Expiration": "EXPIRATION_DATE",
    "RoleArn": "taskRoleArn",
    "SecretAccessKey": "minioadmin",
    "Token": "EC2_TOKEN"
}"""

# utility for mocking an AWS EC2 task
function with(f)
    server = HTTP.serve!(50397) do req
        if req.method == "GET" && req.target == "/latest/meta-data/iam/security-credentials/"
            return HTTP.Response(200, "testRole")
        elseif req.method == "GET" && req.target == "/latest/meta-data/iam/security-credentials/testRole"
            return HTTP.Response(200, RESP)
        elseif req.method == "GET" && req.target == "/latest/meta-data/placement/region"
            return HTTP.Response(200, "us-west-1")
        else
            return HTTP.Response(404)
        end
    end
    try
        f()
    finally
        close(server)
    end
end

end # module EC2

module AzureVM

using HTTP, URIs

const RESP = """
{
  "access_token": "eyJ0eXAi...",
  "refresh_token": "",
  "expires_in": "3599",
  "expires_on": "1506484173",
  "not_before": "1506480273",
  "resource": "https://storage.azure.com/",
  "token_type": "Bearer"
}"""

# utility for mocking an AzureVM
function with(f)
    server = HTTP.serve!(50398) do req
        if req.method == "GET" && req.target == "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F"
            @assert HTTP.header(req, "Metadata") == "true"
            return HTTP.Response(200, RESP)
        else
            return HTTP.Response(404)
        end
    end
    try
        f()
    finally
        close(server)
    end
end

end # module AzureVM

end # module CloudTest

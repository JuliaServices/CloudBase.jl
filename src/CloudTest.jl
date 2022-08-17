module CloudTest

export Minio, Azurite, ECS, EC2

import ..CloudAccount, ..AWS, ..Azure, ..AbstractStore

struct Config
    account::CloudAccount
    store::AbstractStore
    port::Int
    dir::String
    process
end

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

module Minio

using minio_jll, Scratch
import ..Config, ..findOpenPorts, ...AWS

# minio server directory, populated in __init__
const MINIO_DIR = Ref{String}()

function with(f; dir=nothing, bucket=nothing, public=false)
    config, proc = run(dir, bucket, public)
    try
        f(config)
    finally
        kill(proc)
        i = 0
        while !success(proc)
            sleep(0.1)
            i += 1
            if i > 100
                @warn "minio server process didn't exit as expected within 10 seconds"
                break # give up waiting for process to finish
            end
        end
        rm(config.dir; force=true, recursive=true)
    end
    return
end

function run(dir=nothing, bucket=nothing, public=false)
    isdefined(MINIO_DIR, :x) || throw(ArgumentError("minio scratch space not automatically populated; can't run minio server"))
    if dir === nothing
        dir = mktempdir(MINIO_DIR[])
    else !isdir(dir)
        throw(ArgumentError("provided minio directory `$dir` doesn't exist; can't run minio server"))
    end
    p, port = findOpenPorts(2) do ports
        port, cport = ports
        cmd = `$(minio_jll.minio()) server $dir --address :$(port) --console-address :$(cport)`
        p = Base.run(cmd; wait=false)
        sleep(0.25) # sleep just a little for server startup
        return p, port
    end
    account = AWS.Account("minioadmin", "minioadmin")
    bkt = AWS.Bucket(something(bucket, "jl-minio-$(abs(rand(Int16)))"); host="http://127.0.0.1:$port")
    headers = public ? ["X-Amz-Acl" => "public-read-write"] : []
    resp = AWS.put(bkt.baseurl, headers; service="s3", account)
    resp.status == 200 || throw(ArgumentError("unable to create minio bucket `$bkt`"))
    return Config(account, bkt, port, dir, p), p
end

function __init__()
    MINIO_DIR[] = @get_scratch!("MINIO_DIR")
    return
end

end # module Minio

module Azurite

using NodeJS_16_jll, azurite_jll, Scratch
import ..Config, ..findOpenPorts, ...Azure

# azurite server directory, populated in __init__
const AZURITE_DIR = Ref{String}()

function with(f; dir=nothing, container=nothing, public=false)
    config, proc = run(dir, container, public)
    try
        f(config)
    finally
        kill(proc)
        i = 0
        while !success(proc)
            sleep(0.1)
            i += 1
            if i > 100
                @warn "azurite server process didn't exit as expected within 10 seconds"
                break # give up waiting for process to finish
            end
        end
        rm(config.dir; force=true, recursive=true)
    end
    return
end

function run(dir=nothing, container=nothing, public=false)
    isdefined(AZURITE_DIR, :x) || throw(ArgumentError("azurite scratch space not automatically populated; can't run azurite server"))
    if dir === nothing
        dir = mktempdir(AZURITE_DIR[])
    else !isdir(dir)
        throw(ArgumentError("provided azurite directory `$dir` doesn't exist; can't run azurite server"))
    end
    p, port = findOpenPorts(3) do ports
        port, qport, tport = ports
        cmd = `$(node()) $(azurite) -l $dir -d $(joinpath(dir, "debug.log")) --blobPort $port --queuePort $qport --tablePort $tport`
        p = Base.run(cmd; wait=false)
        sleep(0.25) # sleep just a little for server startup
        return p, port
    end
    bkt = something(container, "jl-azurite-$(abs(rand(Int16)))")
    acct = "devstoreaccount1"
    key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
    headers = public ? ["x-ms-blob-public-access" => "container"] : []
    resp = Azure.put("http://127.0.0.1:$port/$acct/$bkt?restype=container", headers; account=acct, key=key)
    resp.status == 201 || throw(ArgumentError("unable to create azurite container `$bkt`"))
    return Config(port, dir, bkt, acct, key, p), p
end

function __init__()
    AZURITE_DIR[] = @get_scratch!("AZURITE_DIR")
    return
end

end # module Azurite

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

end # module CloudTest

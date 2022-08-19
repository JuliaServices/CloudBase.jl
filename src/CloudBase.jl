module CloudBase

export CloudTest

using Dates, Base64, Sockets
using HTTP, URIs, SHA, LoggingExtras, Figgy

abstract type CloudAccount end
abstract type AbstractStore end

_some(x, y) = x === nothing ? y : x

function canconnect(ip, port, timeout=0.01)
    tcp = Sockets.TCPSocket()
    try
        Sockets.connect!(tcp, ip, port)
        sleep(timeout)
        return tcp.status == Base.StatusOpen
    catch e
        # println(sprint(showerror, e))
        return false
    finally
        close(tcp)
    end
end

include("aws.jl")
include("azure.jl")

# custom stream layer to be included right before actual request
# is sent to ensure header timestamps are as correct as possible
function cloudsignlayer(handler)
    return function(stream; aws::Bool=false, azure::Bool=false, kw...)
        req = stream.message.request
        aws && awssign!(req; kw...)
        azure && azuresign!(req; kw...)
        return handler(stream; kw...)
    end
end

# AWS module for signaling AWS request signing
module AWS

using HTTP
import ..cloudsignlayer, ..AWSCredentials, ..AbstractStore, ..AWS_DEFAULT_REGION

awslayer(handler) = (req; kw...) -> handler(req; aws=true, kw...)

HTTP.@client (first=(awslayer,), last=()) (first=(), last=(cloudsignlayer,))

const Credentials = AWSCredentials

struct Bucket <: AbstractStore
    name::String
    baseurl::String

    function Bucket(name::String, region::String=AWS_DEFAULT_REGION; host::Union{Nothing, String}=nothing)
        baseurl = host === nothing ? "https://$name.s3.$region.amazonaws.com/" : "$host/$name/"
        return new(name, baseurl)
    end
end

end # module AWS

# Azure module for signaling Azure request signing
module Azure

using HTTP
import ..cloudsignlayer, ..AzureCredentials, ..AbstractStore

azurelayer(handler) = (req; kw...) -> handler(req; azure=true, kw...)

HTTP.@client (first=(azurelayer,), last=()) (first=(), last=(cloudsignlayer,))

const Credentials = AzureCredentials

struct Container <: AbstractStore
    name::String
    baseurl::String

    function Container(name::String, account::String; host::Union{Nothing, String}=nothing)
        baseurl = host === nothing ? "https://$account.blob.core.windows.net/$name/" : "$host/$account/$name/"
        return new(name, baseurl)
    end
end

end # module Azure

include("CloudTest.jl")

end # module CloudBase

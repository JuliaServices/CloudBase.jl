module CloudBase

export AWS, Azure

using Dates, Base64, Sockets
using HTTP, URIs, SHA, LoggingExtras, Figgy

abstract type CloudCredentials end

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
import ..cloudsignlayer

awslayer(handler) = (req; kw...) -> handler(req; aws=true, kw...)

HTTP.@client (first=(awslayer,), last=()) (first=(), last=(cloudsignlayer,))

end # module AWS

# Azure module for signaling Azure request signing
module Azure

using HTTP
import ..cloudsignlayer

azurelayer(handler) = (req; kw...) -> handler(req; azure=true, kw...)

HTTP.@client (first=(azurelayer,), last=()) (first=(), last=(cloudsignlayer,))

end # module Azure

function __init__()
    awsLoadConfig!()
    azureLoadConfig!()
    return
end

end # module CloudBase

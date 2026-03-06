const GCP_DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

abstract type GCPAuth end

struct AccessToken <: GCPAuth
    token::String
end

Base.show(io::IO, ::AccessToken) = print(io, "AccessToken(****)")

abstract type GCPSource end

struct StaticAuthSource <: GCPSource
    auth::GCPAuth
end

Base.show(io::IO, ::StaticAuthSource) = print(io, "StaticAuthSource(...)")

mutable struct GCPCredentials <: CloudCredentials
    lock::ReentrantLock
    source::GCPSource
    auth::GCPAuth
    expiration::Union{Nothing, DateTime}
    expireThreshold::Dates.Period
    scopes::Vector{String}
end

GCPCredentials(source::GCPSource, auth::GCPAuth, expiration, expireThreshold, scopes::Vector{String}) =
    GCPCredentials(ReentrantLock(), source, auth, expiration, expireThreshold, scopes)

function Base.show(io::IO, creds::GCPCredentials)
    print(io, "GCPCredentials(")
    print(io, "source=")
    show(io, creds.source)
    print(io, ",auth=")
    show(io, creds.auth)
    print(io, ",expiration=", creds.expiration, ",")
    print(io, "expireThreshold=", creds.expireThreshold, ",")
    print(io, "scopes=", creds.scopes, ")")
end

function GCPCredentials(access_token::String, expiration=nothing; expireThreshold=Dates.Minute(5), scopes::Vector{String}=copy(GCP_DEFAULT_SCOPES))
    auth = AccessToken(access_token)
    return GCPCredentials(StaticAuthSource(auth), auth, expiration, expireThreshold, copy(scopes))
end

function getCredentials(x::GCPCredentials)
    Base.@lock x.lock begin
        return x.auth
    end
end

function gcpsign!(request::HTTP.Request; credentials::Union{Nothing, GCPCredentials}=nothing, kw...)
    credentials === nothing && return
    auth = getCredentials(credentials)
    auth isa AccessToken || throw(ArgumentError("unsupported GCP credentials type `$(typeof(auth))`"))
    HTTP.removeheader(request, "Authorization")
    HTTP.setheader(request, "Authorization" => "Bearer $(auth.token)")
    return
end

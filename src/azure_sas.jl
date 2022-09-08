struct SignedVersion
    sv::String
end
SignedVersion() = SignedVersion("2020-12-06")

struct SignedServices
    ss::String
end

SignedServices(; blob::Bool=true, queue::Bool=false, table::Bool=false, file::Bool=false) =
    SignedServices(string(blob ? "b" : "", queue ? "q" : "", table ? "t" : "", file ? "f" : ""))

struct SignedResourceTypes
    srt::String
end

SignedResourceTypes(; service::Bool=false, container::Bool=false, object::Bool=true) =
    SignedResourceTypes(string(service ? "s" : "", container ? "c" : "", object ? "o" : ""))

struct SignedPermission
    sp::String
end

"""
    SignedPermission(; kw...)
    SignedPermission(::String)

Specify signed permissions when generating an Azure SAS URL.

For account-level SAS, the following permissions are allowed (`char`, `keyword arg`: desc):
  * `r`, `read`: Read
  * `w`, `write`: Write
  * `d`, `delete`: Delete
  * `y`, `permanentDelete`: Permanent delete
  * `l`, `list`: List
  * `a`, `add`: Add
  * `c`, `create`: Create
  * `u`, `update`: Update
  * `p`, `process`: Process
  * `t`, `tag`: Tag
  * `f`, `filter`: Filter
  * `i`, `setImmutabilityPolicy`: Set Immutability Policy

For service-level SAS, the following permissions are allowed (`char`, `keyword arg`: desc):
  * `r`, `read`: Read
  * `a`, `add`: Add
  * `c`, `create`: Create
  * `w`, `write`: Write
  * `d`, `delete`: Delete
  * `x`, `deleteVersion`: Delete Version
  * `y`, `permanentDelete`: Permanent delete
  * `l`, `list`: List
  * `u`, `update`: Update
  * `t`, `tag`: Tag
  * `f`, `find`: Find
  * `m`, `move`: Move
  * `e`, `execute`: Execute
  * `o`, `ownership`: Ownership
  * `p`, `permissions`: Permissions
  * `i`, `setImmutabilityPolicy`: Set Immutability Policy
"""
SignedPermission(;
    read::Bool=true,
    add::Bool=false,
    create::Bool=false,
    write::Bool=false,
    update::Bool=false,
    delete::Bool=false,
    deleteVersion::Bool=false,
    permanentDelete::Bool=false,
    list::Bool=false,
    tag::Bool=false,
    find::Bool=false,
    move::Bool=false,
    execute::Bool=false,
    ownership::Bool=false,
    permissions::Bool=false,
    process::Bool=false,
    filter::Bool=false,
    setImmutabilityPolicy::Bool=false) =
    SignedPermission(string(
        read ? "r" : "",
        add ? "a" : "",
        create ? "c" : "",
        write ? "w" : "",
        update ? "u" : "",
        delete ? "d" : "",
        deleteVersion ? "x" : "",
        permanentDelete ? "y" : "",
        list ? "l" : "",
        tag ? "t" : "",
        find ? "f" : "",
        move ? "m" : "",
        execute ? "e" : "",
        ownership ? "o" : "",
        permissions ? "p" : "",
        process ? "p" : "",
        filter ? "f" : "",
        setImmutabilityPolicy ? "i" : ""
    ))

struct SignedStart
    st::String
end

const DF = DateFormat("yyyy-mm-dd\\THH:MM:SS\\Z")
SignedStart(start::DateTime) = SignedStart(Dates.format(start, DF))

struct SignedExpiry
    se::String
end

SignedExpiry(expiry::DateTime=Dates.now(UTC) + Day(1)) = SignedExpiry(Dates.format(expiry, DF))

struct SignedIP
    sip::String
end

SignedIP(first, last) = SignedIP("$first-$last")

struct SignedProtocol
    spr::String

    SignedProtocol(x) = (x == "https,http" || x == "https") ? new(x) : throw(ArgumentError("valid SignedProtocol values are `https,http` or `https`"))
end

SignedProtocol() = SignedProtocol("https,http")

struct SignedEncryptionScope
    ses::String
end

str(x::T) where {T} = getfield(x, 1)
str(::Nothing) = ""

function parseAzureAccountContainerBlob(url)
    # https://myaccount.blob.core.windows.net/mycontainer/myblob
    # https://myaccount.blob.core.windows.net/mycontainer
    m = match(r"^https://(?<account>[^\.]+)\.(?<service>[^\.]+)\.core\.windows\.net/(?<container>[^/]+)(?:/(?<blob>.+))?$", url)
    m !== nothing && return (String(m[:account]), String(m[:service]), String(m[:container]), String(something(m[:blob], "")))
    # https://127.0.0.1:10000/myaccount/mycontainer/myblob
    m = match(r"^https://127\.0\.0\.1:[\d]+/(?<account>[^\.]+?)/(?<container>[^/]+)(?:/(?<blob>.+))?$", url)
    m !== nothing && return (String(m[:account]), "blob", String(m[:container]), String(something(m[:blob], "")))
    throw(ArgumentError("unable to parse azure account from url: `$url`"))
end

function generateAccountSASToken(url::URI, key::String;
    signedVersion=SignedVersion(),
    signedServices=SignedServices(),
    signedResourceTypes=SignedResourceTypes(),
    signedPermission=SignedPermission(),
    signedStart=nothing,
    signedExpiry=SignedExpiry(),
    signedIP=nothing,
    signedProtocol=nothing,
    signedEncryptionScope=nothing)

    account, _, _, _ = parseAzureAccountContainerBlob(string(url))
    stringToSign = """$account
    $(str(signedPermission))
    $(str(signedServices))
    $(str(signedResourceTypes))
    $(str(signedStart))
    $(str(signedExpiry))
    $(str(signedIP))
    $(str(signedProtocol))
    $(str(signedVersion))
    $(str(signedEncryptionScope))
    """
    sig = base64encode(hmac_sha256(base64decode(key), stringToSign))
    # println(stringToSign)
    # @show sig
    query = URIs.queryparams(url)
    for x in (signedVersion, signedServices, signedResourceTypes, signedPermission, signedStart, signedExpiry, signedIP, signedProtocol, signedEncryptionScope)
        if !isnothing(x)
            query[String(fieldname(typeof(x), 1))] = getfield(x, 1)
        end
    end
    query["sig"] = sig
    return URIs.escapeuri(query)
end

generateAccountSASToken(uri::String, key::String; kw...) = generateAccountSASToken(URI(uri), key; kw...)
generateAccountSASURI(uri::URI, key::String; kw...) = URI(uri; query=generateAccountSASToken(uri, key; kw...))
generateAccountSASURI(uri::String, key::String; kw...) = generateAccountSASURI(URI(uri), key; kw...)

struct SignedResource
    sr::String
end

SignedResource(; container::Bool=false, blob::Bool=true, blobVersion::Bool=false, blobSnapshot::Bool=false, directory::Bool=false, file::Bool=false, share::Bool=false) =
    SignedResource(string(container ? "c" : "", blob ? "b" : "", blobVersion ? "bv" : "", blobSnapshot ? "bs" : "", directory ? "d" : "", file ? "f" : "", share ? "s" : ""))

struct SignedDirectoryDepth
    sdd::Int
end

struct CacheControl
    rscc::String
end

struct ContentDisposition
    rscd::String
end

struct ContentEncoding
    rsce::String
end

struct ContentLanguage
    rscl::String
end

struct ContentType
    rscl::String
end

struct TableName
    tn::String
end

struct StartPk
    spk::String
end

struct StartRk
    srk::String
end

struct EndPk
    epk::String
end

struct EndRk
    erk::String
end

struct SignedIdentifier
    si::String
end

struct SignedSnapshotTime
    sst::String
end

function getCanonicalizedResource(url)
    account, service, container, blob = parseAzureAccountContainerBlob(string(url))
    if service == "table"
        # Employees(PartitionKey='Jeff',RowKey='Price')
        # we want to regex match only Employees
        m = match(r"^(?<table>.*?)(?<pk>\(PartitionKey='(?<pkv>.*?)',RowKey='(?<rkv>.*?)'\))?$", container)
        container = lowercase(m[:table])
    end
    return rstrip(joinpath("/", service, account, container, blob), '/'), service
end

function generateServiceSASToken(url::URI, key::String;
    signedVersion=SignedVersion(),
    signedPermission=SignedPermission(),
    signedStart=nothing,
    signedExpiry=SignedExpiry(),
    signedIP=nothing,
    signedProtocol=nothing,
    signedEncryptionScope=nothing,
    signedResource=SignedResource(),
    signedDirectoryDepth=nothing,
    cacheControl=nothing,
    contentDisposition=nothing,
    contentEncoding=nothing,
    contentLanguage=nothing,
    contentType=nothing,
    tableName=nothing,
    startPk=nothing,
    startRk=nothing,
    endPk=nothing,
    endRk=nothing,
    signedIdentifier=nothing,
    signedSnapshotTime=nothing)

    canonicalizedResource, service = getCanonicalizedResource(url)
    if service == "queue"
        stringToSign = """$(str(signedPermission))
        $(str(signedStart))
        $(str(signedExpiry))
        $canonicalizedResource
        $(str(signedIdentifier))
        $(str(signedIP))
        $(str(signedProtocol))
        $(str(signedVersion))"""
    elseif service == "table"
        stringToSign = """$(str(signedPermission))
        $(str(signedStart))
        $(str(signedExpiry))
        $canonicalizedResource
        $(str(signedIdentifier))
        $(str(signedIP))
        $(str(signedProtocol))
        $(str(signedVersion))
        $(str(startPk))
        $(str(startRk))
        $(str(endPk))
        $(str(endRk))"""
    else
        stringToSign = """$(str(signedPermission))
        $(str(signedStart))
        $(str(signedExpiry))
        $canonicalizedResource
        $(str(signedIdentifier))
        $(str(signedIP))
        $(str(signedProtocol))
        $(str(signedVersion))
        $(str(signedResource))
        $(str(signedSnapshotTime))
        $(str(signedEncryptionScope))
        $(str(cacheControl))
        $(str(contentDisposition))
        $(str(contentEncoding))
        $(str(contentLanguage))
        $(str(contentType))"""
    end
    sig = base64encode(hmac_sha256(base64decode(key), stringToSign))
    # println(stringToSign)
    # @show sig
    query = URIs.queryparams(url)
    for x in (signedVersion, signedPermission, signedStart, signedExpiry, signedIP, signedProtocol, signedEncryptionScope, signedResource, signedSnapshotTime, cacheControl, contentDisposition, contentEncoding, contentLanguage, contentType, tableName, startPk, startRk, endPk, endRk, signedIdentifier)
        if !isnothing(x)
            query[String(fieldname(typeof(x), 1))] = getfield(x, 1)
        end
    end
    query["sig"] = sig
    return URIs.escapeuri(query)
end

generateServiceSASToken(uri::String, key::String; kw...) = generateServiceSASToken(URI(uri), key; kw...)
generateServiceSASURI(uri::URI, key::String; kw...) = URI(uri; query=generateServiceSASToken(uri, key; kw...))
generateServiceSASURI(uri::String, key::String; kw...) = generateServiceSASURI(URI(uri), key; kw...)

# user delegation
struct SignedObjectId
    skoid::String
end

struct SignedTenantId
    sktid::String
end

struct SignedKeyStartTime
    skt::String
end

struct SignedKeyExpiryTime
    ske::String
end

struct SignedKeyService
    sks::String
end

struct SignedKeyVersion
    skv::String
end

struct SignedAuthorizedObjectId
    saoid::String
end

struct SignedUnauthorizedObjectId
    suoid::String
end

struct SignedCorrelationId
    scid::String
end

# exampleBody = """
# <?xml version="1.0" encoding="utf-8"?>
# <UserDelegationKey>
#     <SignedOid>String containing a GUID value</SignedOid>
#     <SignedTid>String containing a GUID value</SignedTid>
#     <SignedStart>String formatted as ISO date</SignedStart>
#     <SignedExpiry>String formatted as ISO date</SignedExpiry>
#     <SignedService>b</SignedService>
#     <SignedVersion>String specifying REST api version to use to create the user delegation key</SignedVersion>
#     <Value>String containing the user delegation key</Value>
# </UserDelegationKey>"""
function parseGetUserDelegationKeyBody(body)
    # do a regex match against SignedOid, SignedTid, SignedStart, SignedExpiry, SignedService, SignedVersion, Value
    m = match(r"<SignedOid>(?<skoid>.*?)</SignedOid>\s*<SignedTid>(?<sktid>.*?)</SignedTid>\s*<SignedStart>(?<skt>.*?)</SignedStart>\s*<SignedExpiry>(?<ske>.*?)</SignedExpiry>\s*<SignedService>(?<sks>.*?)</SignedService>\s*<SignedVersion>(?<skv>.*?)</SignedVersion>\s*<Value>(?<value>.*?)</Value>", body)
    return SignedObjectId(m[:skoid]), SignedTenantId(m[:sktid]), SignedKeyStartTime(m[:skt]), SignedKeyExpiryTime(m[:ske]), SignedKeyService(m[:sks]), SignedKeyVersion(m[:skv]), m[:value]
end

function parseBaseUrl(url)
    # we want to generate this url: # http://127.0.0.1:10000/devstoreaccount1/?restype=service&comp=userdelegationkey
    # from a resource url like: # https://127.0.0.1:10000/myaccount/mycontainer/myblob
    if url.host == "127.0.0.1"
        m = match(r"^(?<baseurl>.*?)/(?<account>.*?)/", string(url))
        m === nothing && throw(ArgumentError("couldn't parse base url from provided url: `$url`"))
        return joinpath(m[:baseurl], m[:account])
    else
        m = match(r"^(?<baseurl>.*?)/", url)
        m === nothing && throw(ArgumentError("couldn't parse base url from provided url: `$url`"))
        return m[:baseurl]
    end
end

function getUserDelegationKey(url, signedStart=nothing, signedExpiry=SignedExpiry(); credentials::AzureCredentials, kw...)
    # https://myaccount.blob.core.windows.net/?restype=service&comp=userdelegationkey
    # http://127.0.0.1:10000/devstoreaccount1/?restype=service&comp=userdelegationkey
    url = URI(URI(parseBaseUrl(url)); query=Dict("restype" => "service", "comp" => "userdelegationkey"))
    signedStart = something(signedStart, SignedStart(Dates.now(UTC))).st
    body = "<KeyInfo><Start>$(signedStart)</Start><Expiry>$(signedExpiry.se)</Expiry></KeyInfo>"
    credentials.auth isa AccessToken || throw(ArgumentError("generating user delegation SAS requires access token credentials"))
    resp = Azure.post(url, [], body; credentials, kw...)
    return parseGetUserDelegationKeyBody(String(resp.body))
end

function generateUserDelegationSASToken(url::URI;
    signedVersion=SignedVersion(),
    signedResource=SignedResource(),
    signedStart=nothing,
    signedExpiry=SignedExpiry(),
    signedPermission=SignedPermission(),
    signedIP=nothing,
    signedProtocol=nothing,
    signedDirectoryDepth=nothing,
    cacheControl=nothing,
    contentDisposition=nothing,
    contentEncoding=nothing,
    contentLanguage=nothing,
    contentType=nothing,
    signedEncryptionScope=nothing,
    signedAuthorizedObjectId=nothing,
    signedUnauthorizedObjectId=nothing,
    signedCorrelationId=nothing,
    signedSnapshotTime=nothing, kw...)

    canonicalizedResource = getCanonicalizedResource(url)
    signedKeyObjectId,
        signedKeyTenantId,
        signedKeyStartTime,
        signedKeyExpiryTime,
        signedKeyService,
        signedKeyVersion,
        key = getUserDelegationKey(url, signedStart, signedExpiry; kw...)
    stringToSign = """$(str(signedPermission))
        $(str(signedStart))
        $(str(signedExpiry))
        $canonicalizedResource
        $(str(signedKeyObjectId))
        $(str(signedKeyTenantId))
        $(str(signedKeyStartTime))
        $(str(signedKeyExpiryTime))
        $(str(signedKeyService))
        $(str(signedKeyVersion))
        $(str(signedAuthorizedObjectId))
        $(str(signedUnauthorizedObjectId))
        $(str(signedCorrelationId))
        $(str(signedIP))
        $(str(signedProtocol))
        $(str(signedVersion))
        $(str(signedResource))
        $(str(signedSnapshotTime))
        $(str(signedEncryptionScope))
        $(str(cacheControl))
        $(str(contentDisposition))
        $(str(contentEncoding))
        $(str(contentLanguage))
        $(str(contentType))"""
    sig = base64encode(hmac_sha256(base64decode(key), stringToSign))
    # println(stringToSign)
    # @show sig
    query = URIs.queryparams(url)
    for x in (signedPermission, signedStart, signedExpiry, signedIP, signedProtocol, signedVersion, signedResource, signedSnapshotTime, signedEncryptionScope, cacheControl, contentDisposition, contentEncoding, contentLanguage, contentType, signedKeyObjectId, signedKeyTenantId, signedKeyStartTime, signedKeyExpiryTime, signedKeyService, signedKeyVersion, signedAuthorizedObjectId, signedUnauthorizedObjectId, signedCorrelationId)
        if !isnothing(x)
            query[String(fieldname(typeof(x), 1))] = getfield(x, 1)
        end
    end
    query["sig"] = sig
    return URIs.escapeuri(query)
end

generateUserDelegationSASToken(uri::String, key::String; kw...) = generateUserDelegationSASToken(URI(uri), key; kw...)
generateUserDelegationSASURI(uri::URI, key::String; kw...) = URI(uri; query=generateUserDelegationSASToken(uri, key; kw...))
generateUserDelegationSASURI(uri::String, key::String; kw...) = generateUserDelegationSASURI(URI(uri), key; kw...)

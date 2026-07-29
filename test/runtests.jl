using CloudBase, Test, CloudBase.CloudTest, JSON3, JSON, Dates, HTTP, OpenSSL
using CloudBase: AWS, Azure, GCP
using Sockets, Random

const x32bit = Sys.WORD_SIZE == 32

function verifyRS256(private_key::String, message::String, signature::Vector{UInt8})
    key = OpenSSL.EvpPKey(private_key)
    ctx = OpenSSL.EvpDigestContext()
    digest = OpenSSL.EvpSHA256()
    if ccall((:EVP_DigestVerifyInit, OpenSSL.libcrypto), Cint,
            (OpenSSL.EvpDigestContext, Ptr{Cvoid}, OpenSSL.EvpDigest, Ptr{Cvoid}, OpenSSL.EvpPKey),
            ctx, C_NULL, digest, C_NULL, key) != 1
        throw(OpenSSL.OpenSSLError())
    end
    data = Vector{UInt8}(codeunits(message))
    GC.@preserve data begin
        if ccall((:EVP_DigestVerifyUpdate, OpenSSL.libcrypto), Cint,
                (OpenSSL.EvpDigestContext, Ptr{UInt8}, Csize_t),
                ctx, pointer(data), length(data)) != 1
            throw(OpenSSL.OpenSSLError())
        end
    end
    GC.@preserve signature begin
        return ccall((:EVP_DigestVerifyFinal, OpenSSL.libcrypto), Cint,
            (OpenSSL.EvpDigestContext, Ptr{UInt8}, Csize_t),
            ctx, pointer(signature), length(signature)) == 1
    end
end

headerdict(headers) = Dict(String(k) => String(v) for (k, v) in headers)

function requireenv(name::String)
    haskey(ENV, name) || error("missing required live-test environment variable `$name`")
    return ENV[name]
end

function liveGCPCredentials()
    quota_project_id = get(ENV, "CLOUDBASE_GCP_LIVE_QUOTA_PROJECT", "")
    if haskey(ENV, "CLOUDBASE_GCP_LIVE_HMAC_ACCESS_ID") && haskey(ENV, "CLOUDBASE_GCP_LIVE_HMAC_SECRET")
        return GCP.Credentials(
            ENV["CLOUDBASE_GCP_LIVE_HMAC_ACCESS_ID"],
            ENV["CLOUDBASE_GCP_LIVE_HMAC_SECRET"];
            quota_project_id,
        )
    elseif haskey(ENV, "CLOUDBASE_GCP_LIVE_ACCESS_TOKEN")
        return GCP.Credentials(ENV["CLOUDBASE_GCP_LIVE_ACCESS_TOKEN"]; quota_project_id)
    elseif haskey(ENV, "CLOUDBASE_GCP_LIVE_CREDENTIALS_FILE")
        return GCP.Credentials(; application_credentials_file=ENV["CLOUDBASE_GCP_LIVE_CREDENTIALS_FILE"])
    elseif haskey(ENV, CloudBase.GCP_APPLICATION_CREDENTIALS_ENV)
        return GCP.Credentials()
    end
    error("set one of `CLOUDBASE_GCP_LIVE_ACCESS_TOKEN`, `CLOUDBASE_GCP_LIVE_CREDENTIALS_FILE`, `$((CloudBase.GCP_APPLICATION_CREDENTIALS_ENV))`, or the HMAC pair `CLOUDBASE_GCP_LIVE_HMAC_ACCESS_ID` / `CLOUDBASE_GCP_LIVE_HMAC_SECRET`")
end

@testset "AWSSigV4" begin
    file = abspath(joinpath(dirname(pathof(CloudBase)), "../test/resources/awsSig4Cases.json"))
    cases = JSON3.read(read(file))
    configs = copy(cases.config)
    configs[:credentials] = CloudBase.AWSCredentials(configs[:accessKeyId], configs[:secretAccessKey])
    delete!(configs, :accessKeyId)
    delete!(configs, :secretAccessKey)
    debug = false
    knownFailures = (19, 20, 23, 26)
    for (i, case) in enumerate(cases.tests.all)
        println("testing AWSSig4 case = $(case.name), i = $i")
        hdrs = Pair{String,String}[String(h[1]) => String(h[2]) for h in case.request.headers]
        req = HTTP.Request(case.request.method, case.request.path, hdrs, case.request.body)
        CloudBase.awssign!(req, HTTP.URI(case.request.uri); x_amz_date=DateTime(2015, 8, 30, 12, 36), includeContentSha256=false, debug=debug, configs...)
        if i in knownFailures
            @test_broken HTTP.header(req, "Authorization") == case.authz
        else
            @test HTTP.header(req, "Authorization") == case.authz
        end
    end
end

@testset "AWSSigV2" begin
    req = HTTP.Request("GET", "/?Action=DescribeJobFlows")
    credentials = CloudBase.AWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    CloudBase.awssignv2!(req, HTTP.URI("https://elasticmapreduce.amazonaws.com?Action=DescribeJobFlows"); credentials, timestamp=DateTime(2011, 10, 3, 15, 19, 30), version="2009-03-31")
    @test req.target ==
        "?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Action=DescribeJobFlows&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2011-10-03T15%3A19%3A30&Version=2009-03-31&Signature=i91nKc4PWAt0JJIdXwz9HxZCJDdiy6cf%2FMj6vPxyYIs%3D"
    req = HTTP.Request("POST", "/", Pair{String,String}[], HTTP.escapeuri(Dict("Action" => "DescribeJobFlows")))
    CloudBase.awssignv2!(req, HTTP.URI("https://elasticmapreduce.amazonaws.com"); credentials, timestamp=DateTime(2011, 10, 3, 15, 19, 30), version="2009-03-31")
    signed = HTTP.URIs.queryparams(HTTP.URI("?" * String(copy(CloudBase.requestbodybytes(req)))))
    @test signed["Signature"] == "wseguMzBRgA/4/fan8ZwEa0PIF+ws4WFbTJcG1ts5RY="
end

@time @testset "AWS" begin
    config = Ref{Any}()
    Minio.with(bindIP="127.0.0.1", startupDelay=0.5, waitForPortTimeout=10) do conf
        config[] = conf
        credentials, bucket = conf
        csv = "a,b,c\n1,2,3\n4,5,$(rand())"
        AWS.put("$(bucket.baseurl)test.csv", [], csv; service="s3", credentials)
        resp = AWS.get("$(bucket.baseurl)test.csv"; service="s3", credentials)
        @test String(resp.body) == csv
    end
    @test !isdir(config[].dir)
    @test success(config[].process)
    # test public access
    Minio.with(bindIP="127.0.0.1", startupDelay=0.5, public=true) do conf
        credentials, bucket = conf
        csv = "a,b,c\n1,2,3\n4,5,$(rand())"
        AWS.put("$(bucket.baseurl)test.csv", [], csv; service="s3")
        resp = AWS.get("$(bucket.baseurl)test.csv"; service="s3")
        @test String(resp.body) == csv
        # list is public
        resp = AWS.get("$(bucket.baseurl)?list-type=2"; service="s3")
        @test resp.status == 200
        # delete is also public
        resp = AWS.delete("$(bucket.baseurl)test.csv"; service="s3")
        @test resp.status == 204
    end
end

if !x32bit
@time @testset "Azure" begin
    config = Ref{Any}()
    Azurite.with(startupDelay=0.5, waitForPortTimeout=10) do conf
        config[] = conf
        credentials, container = conf
        csv = "a,b,c\n1,2,3\n4,5,$(rand())"
        Azure.put("$(container.baseurl)test", ["x-ms-blob-type" => "BlockBlob"], csv; credentials)
        resp = Azure.get("$(container.baseurl)test"; credentials)
        @test String(resp.body) == csv
        # test SAS generation
        # account-level
        url = "$(container.baseurl)test2"
        key = credentials.auth.key
        sas = CloudBase.generateAccountSASURI(url, key; signedPermission=CloudBase.SignedPermission("rw"))
        resp = HTTP.put(sas, ["x-ms-blob-type" => "BlockBlob"], csv; require_ssl_verification=false)
        resp = HTTP.get(sas; require_ssl_verification=false)
        @test String(resp.body) == csv
        # service-level
        url = "$(container.baseurl)test3"
        sas = CloudBase.generateServiceSASURI(url, key; signedPermission=CloudBase.SignedPermission("rw"))
        resp = HTTP.put(sas, ["x-ms-blob-type" => "BlockBlob"], csv; require_ssl_verification=false)
        resp = HTTP.get(sas; require_ssl_verification=false)
        @test String(resp.body) == csv
        # token for authorization
        creds = Azure.Credentials(CloudBase.generateAccountSASToken(credentials.auth.account, key; signedPermission=CloudBase.SignedPermission("rw")))
        resp = Azure.put("$(container.baseurl)test4", ["x-ms-blob-type" => "BlockBlob"], csv; credentials=creds)
        resp = Azure.get("$(container.baseurl)test4"; credentials=creds)
        @test String(resp.body) == csv
    end
    @test !isdir(config[].dir)
    @test success(config[].process)
    # test public access
    Azurite.with(startupDelay=0.5, public=true) do conf
        credentials, container = conf
        csv = "a,b,c\n1,2,3\n4,5,$(rand())"
        # have to supply credentials for put since "public" is only for get
        Azure.put("$(container.baseurl)test", ["x-ms-blob-type" => "BlockBlob"], csv; credentials)
        resp = Azure.get("$(container.baseurl)test")
        @test String(resp.body) == csv
        # list is public
        resp = Azure.get("$(container.baseurl)?comp=list&restype=container")
        @test resp.status == 200
        # but delete also requires credentials
        Azure.delete("$(container.baseurl)test"; credentials)
    end
end
end

@testset "Concurrent Minio/Azurite test servers" begin
    mconfigs = Vector{Any}(undef, 10)
    aconfigs = Vector{Any}(undef, 10)
    @sync for i = 1:10
        @async Minio.with(bindIP="127.0.0.1", startupDelay=0.5) do conf
            mconfigs[i] = conf
            credentials, bucket = conf
            csv = "a,b,c\n1,2,3\n4,5,$(rand())"
            AWS.put("$(bucket.baseurl)test.csv", [], csv; service="s3", credentials)
            resp = AWS.get("$(bucket.baseurl)test.csv"; service="s3", credentials)
            @test String(resp.body) == csv
        end
        if !x32bit
            @async Azurite.with(startupDelay=0.5) do conf
                aconfigs[i] = conf
                credentials, container = conf
                csv = "a,b,c\n1,2,3\n4,5,$(rand())"
                Azure.put("$(container.baseurl)test", ["x-ms-blob-type" => "BlockBlob"], csv; credentials)
                resp = Azure.get("$(container.baseurl)test"; credentials)
                @test String(resp.body) == csv
            end
        end
    end
    for i = 1:10
        @test !isdir(mconfigs[i].dir)
        @test success(mconfigs[i].process)
        if !x32bit
            @test !isdir(aconfigs[i].dir)
            @test success(aconfigs[i].process)
        end
    end
end

@testset "AWS ECS Task" begin
    ECS.with() do
        CloudBase.reloadECSCredentials!("http://127.0.0.1")
        @test get(CloudBase.AWS_CONFIGS, "aws_session_token", "") == "ECS_TOKEN"
    end
end

@testset "AWS EC2" begin
    EC2.with() do
        CloudBase.reloadEC2Credentials!("127.0.0.1", 50397)
        @test get(CloudBase.AWS_CONFIGS, "aws_session_token", "") == "EC2_TOKEN"
        @test get(CloudBase.AWS_CONFIGS, "region", "") == "us-west-1"
    end
end

@testset "AzureVM" begin
    AzureVM.with() do
        CloudBase.reloadAzureVMCredentials!("http://127.0.0.1:50398")
        @test !isempty(get(CloudBase.AZURE_CONFIGS, "access_token", ""))
    end
end

@testset "GCP Access Token" begin
    creds = GCP.Credentials("TEST_TOKEN")
    req = HTTP.Request("GET", "/test")
    CloudBase.gcpsign!(req, HTTP.URI("https://storage.googleapis.com/test-bucket/test"); credentials=creds)
    @test HTTP.header(req, "Authorization") == "Bearer TEST_TOKEN"

    port, socket = Sockets.listenany(IPv4(0), rand(RandomDevice(), 10000:50000))
    close(socket)
    auth_headers = Channel{String}(2)
    server = HTTP.serve!(ip"127.0.0.1", port) do request
        put!(auth_headers, HTTP.header(request, "Authorization"))
        return HTTP.Response(200, "ok")
    end
    try
        resp = GCP.get("http://127.0.0.1:$port/test"; credentials=creds)
        @test resp.status == 200
        @test take!(auth_headers) == "Bearer TEST_TOKEN"

        resp = GCP.get("http://127.0.0.1:$port/public")
        @test resp.status == 200
        @test take!(auth_headers) == ""
    finally
        close(server)
    end
end

@testset "GCP Service Account" begin
    request_ref = Ref{Any}()
    GCPTokenServer.with(; request_ref=request_ref) do request_count
        mktemp() do path, io
            private_key = read(joinpath(dirname(pathof(CloudBase)), "../src/test.key"), String)
            write(io, JSON.json(Dict(
                "type" => "service_account",
                "client_email" => "service-account@test.local",
                "private_key" => private_key,
                "private_key_id" => "test-key-id",
                "token_uri" => "http://127.0.0.1:50399/token",
            )))
            close(io)
            ENV[CloudBase.GCP_APPLICATION_CREDENTIALS_ENV] = path
            try
                creds = GCP.Credentials()
                @test creds.auth isa CloudBase.GCPAccessToken
                @test creds.auth.token == "GCP_SERVICE_ACCOUNT_TOKEN"
                @test request_count[] == 1

                request = request_ref[]
                params = Dict(HTTP.URIs.queryparampairs(HTTP.URI("http://127.0.0.1/?$(request.body)")))
                @test params["grant_type"] == CloudBase.GCP_JWT_GRANT_TYPE

                parts = split(params["assertion"], '.')
                @test length(parts) == 3
                header = JSON.parse(String(CloudBase.base64urldecode(parts[1])))
                payload = JSON.parse(String(CloudBase.base64urldecode(parts[2])))
                @test header["alg"] == "RS256"
                @test header["typ"] == "JWT"
                @test header["kid"] == "test-key-id"
                @test payload["iss"] == "service-account@test.local"
                @test payload["scope"] == join(CloudBase.GCP_DEFAULT_SCOPES, ' ')
                @test payload["aud"] == "http://127.0.0.1:50399/token"
                @test Int(payload["exp"]) - Int(payload["iat"]) == 3600
                @test verifyRS256(private_key, string(parts[1], '.', parts[2]), CloudBase.base64urldecode(parts[3]))

                creds.expiration = Dates.now(Dates.UTC) - Dates.Second(1)
                @sync for _ = 1:8
                    @async begin
                        auth = CloudBase.getCredentials(creds)
                        @test auth.token == "GCP_SERVICE_ACCOUNT_TOKEN"
                    end
                end
                @test request_count[] == 2
            finally
                delete!(ENV, CloudBase.GCP_APPLICATION_CREDENTIALS_ENV)
            end
        end
    end
end

@testset "GCP Authorized User" begin
    request_ref = Ref{Any}()
    response = JSON.json(Dict(
        "access_token" => "GCP_AUTHORIZED_USER_TOKEN",
        "expires_in" => 3599,
        "token_type" => "Bearer",
    ))
    GCPTokenServer.with(; port=50403, response, request_ref=request_ref) do request_count
        temp_home = mktempdir()
        adc_dir = joinpath(temp_home, ".config", "gcloud")
        mkpath(adc_dir)
        JSON.json(joinpath(adc_dir, "application_default_credentials.json"), Dict(
            "type" => "authorized_user",
            "client_id" => "authorized-client-id",
            "client_secret" => "authorized-client-secret",
            "refresh_token" => "authorized-refresh-token",
            "quota_project_id" => "billing-project",
            "token_uri" => "http://127.0.0.1:50403/token",
        ))
        old_home = get(ENV, "HOME", nothing)
        old_gac = get(ENV, CloudBase.GCP_APPLICATION_CREDENTIALS_ENV, nothing)
        delete!(ENV, CloudBase.GCP_APPLICATION_CREDENTIALS_ENV)
        ENV["HOME"] = temp_home
        try
            creds = GCP.Credentials()
            @test creds.auth isa CloudBase.GCPAccessToken
            @test creds.auth.token == "GCP_AUTHORIZED_USER_TOKEN"
            @test request_count[] == 1

            request = request_ref[]
            params = Dict(HTTP.URIs.queryparampairs(HTTP.URI("http://127.0.0.1/?$(request.body)")))
            @test params["grant_type"] == CloudBase.GCP_REFRESH_TOKEN_GRANT_TYPE
            @test params["client_id"] == "authorized-client-id"
            @test params["client_secret"] == "authorized-client-secret"
            @test params["refresh_token"] == "authorized-refresh-token"

            req = HTTP.Request("GET", "/test")
            CloudBase.gcpsign!(req, HTTP.URI("https://storage.googleapis.com/test-bucket/test"); credentials=creds)
            @test HTTP.header(req, "Authorization") == "Bearer GCP_AUTHORIZED_USER_TOKEN"
            @test HTTP.header(req, "x-goog-user-project") == "billing-project"
        finally
            old_home === nothing ? delete!(ENV, "HOME") : (ENV["HOME"] = old_home)
            old_gac === nothing || (ENV[CloudBase.GCP_APPLICATION_CREDENTIALS_ENV] = old_gac)
        end
    end
end

@testset "GCP External Account File Source" begin
    sts_request_ref = Ref{Any}()
    impersonation_request_ref = Ref{Any}()
    GCPSTS.with(; request_ref=sts_request_ref) do sts_request_count
        GCPImpersonation.with(; request_ref=impersonation_request_ref) do impersonation_request_count
            mktempdir() do dir
                subject_token_file = joinpath(dir, "subject-token.json")
                JSON.json(subject_token_file, Dict("id_token" => "FILE_SUBJECT_TOKEN"))
                creds_file = joinpath(dir, "external-account.json")
                JSON.json(creds_file, Dict(
                    "type" => "external_account",
                    "audience" => "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
                    "subject_token_type" => "urn:ietf:params:oauth:token-type:jwt",
                    "token_url" => "http://127.0.0.1:50401/v1/token",
                    "service_account_impersonation_url" => "http://127.0.0.1:50402/v1/projects/-/serviceAccounts/test@example.com:generateAccessToken",
                    "service_account_impersonation" => Dict("token_lifetime_seconds" => 1800),
                    "workforce_pool_user_project" => "external-billing-project",
                    "credential_source" => Dict(
                        "file" => subject_token_file,
                        "format" => Dict(
                            "type" => "json",
                            "subject_token_field_name" => "id_token",
                        ),
                    ),
                ))

                creds = GCP.Credentials(; application_credentials_file=creds_file)
                @test creds.auth isa CloudBase.GCPAccessToken
                @test creds.auth.token == "GCP_IMPERSONATED_TOKEN"
                @test sts_request_count[] == 1
                @test impersonation_request_count[] == 1

                sts_payload = JSON.parse(sts_request_ref[].body)
                @test sts_payload["grantType"] == CloudBase.GCP_TOKEN_EXCHANGE_GRANT_TYPE
                @test sts_payload["requestedTokenType"] == CloudBase.GCP_REQUESTED_TOKEN_TYPE
                @test sts_payload["subjectToken"] == "FILE_SUBJECT_TOKEN"
                @test sts_payload["subjectTokenType"] == "urn:ietf:params:oauth:token-type:jwt"
                @test sts_payload["scope"] == join(CloudBase.GCP_IMPERSONATION_SCOPES, ' ')

                impersonation_headers = headerdict(impersonation_request_ref[].headers)
                @test impersonation_headers["Authorization"] == "Bearer GCP_STS_TOKEN"
                impersonation_payload = JSON.parse(impersonation_request_ref[].body)
                @test impersonation_payload["scope"] == CloudBase.GCP_DEFAULT_SCOPES
                @test impersonation_payload["lifetime"] == "1800s"

                req = HTTP.Request("GET", "/test")
                CloudBase.gcpsign!(req, HTTP.URI("https://storage.googleapis.com/test-bucket/test"); credentials=creds)
                @test HTTP.header(req, "x-goog-user-project") == "external-billing-project"
            end
        end
    end
end

@testset "GCP External Account URL Source" begin
    sts_request_ref = Ref{Any}()
    source_request_ref = Ref{Any}()
    GCPSTS.with(; port=50404, response=JSON.json(Dict(
        "access_token" => "GCP_URL_STS_TOKEN",
        "issued_token_type" => CloudBase.GCP_REQUESTED_TOKEN_TYPE,
        "token_type" => "Bearer",
        "expires_in" => 3599,
    )), request_ref=sts_request_ref) do sts_request_count
        port, socket = Sockets.listenany(IPv4(0), rand(RandomDevice(), 10000:50000))
        close(socket)
        server = HTTP.serve!(ip"127.0.0.1", port) do request
            source_request_ref[] = (method=request.method, target=request.target, headers=copy(request.headers), body=String(request.body))
            return HTTP.Response(200, "URL_SUBJECT_TOKEN")
        end
        try
            mktemp() do path, io
                write(io, JSON.json(Dict(
                    "type" => "external_account",
                    "audience" => "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
                    "subject_token_type" => "urn:ietf:params:oauth:token-type:jwt",
                    "token_url" => "http://127.0.0.1:50404/v1/token",
                    "credential_source" => Dict(
                        "url" => "http://127.0.0.1:$port/subject-token",
                        "headers" => Dict("Metadata" => "True"),
                    ),
                )))
                close(io)
                creds = GCP.Credentials(; application_credentials_file=path)
                @test creds.auth isa CloudBase.GCPAccessToken
                @test creds.auth.token == "GCP_URL_STS_TOKEN"
                @test sts_request_count[] == 1
                @test headerdict(source_request_ref[].headers)["Metadata"] == "True"

                sts_payload = JSON.parse(sts_request_ref[].body)
                @test sts_payload["subjectToken"] == "URL_SUBJECT_TOKEN"
                @test sts_payload["scope"] == join(CloudBase.GCP_DEFAULT_SCOPES, ' ')
            end
        finally
            close(server)
        end
    end
end

@testset "GCP HMAC XML Interop" begin
    bucket = GCP.Bucket("test-bucket")
    @test bucket.baseurl == "https://storage.googleapis.com/test-bucket/"

    creds = GCP.Credentials("HMAC_ACCESS_ID", "HMAC_SECRET"; quota_project_id="test-project")
    request_time = DateTime(2026, 1, 2, 3, 4, 5)
    req = HTTP.Request("PUT", "/test-bucket/test-object", ["Content-Type" => "text/plain"], "hello")
    expected = HTTP.Request("PUT", "/test-bucket/test-object", ["Content-Type" => "text/plain"], "hello")

    CloudBase.gcpsign!(req, HTTP.URI("https://storage.googleapis.com/test-bucket/test-object"); credentials=creds, x_amz_date=request_time)
    HTTP.setheader(expected, "x-amz-project-id" => "test-project")
    CloudBase.awssign!(expected, HTTP.URI("https://storage.googleapis.com/test-bucket/test-object"); service="s3", region="us-east-1", credentials=CloudBase.AWSCredentials("HMAC_ACCESS_ID", "HMAC_SECRET"), x_amz_date=request_time)

    @test HTTP.header(req, "Authorization") == HTTP.header(expected, "Authorization")
    @test HTTP.header(req, "x-amz-date") == HTTP.header(expected, "x-amz-date")
    @test HTTP.header(req, "x-amz-content-sha256") == HTTP.header(expected, "x-amz-content-sha256")
    @test HTTP.header(req, "x-amz-project-id") == "test-project"

    port, socket = Sockets.listenany(IPv4(0), rand(RandomDevice(), 10000:50000))
    close(socket)
    request_ref = Ref{Any}()
    server = HTTP.serve!(ip"127.0.0.1", port) do request
        request_ref[] = (method=request.method, target=request.target, headers=copy(request.headers), body=String(request.body))
        return HTTP.Response(200, "ok")
    end
    try
        resp = GCP.get("http://127.0.0.1:$port/test-bucket/test-object"; credentials=creds, x_amz_date=request_time)
        @test resp.status == 200
        headers = headerdict(request_ref[].headers)
        @test startswith(headers["Authorization"], "AWS4-HMAC-SHA256 Credential=HMAC_ACCESS_ID/")
        @test headers["x-amz-project-id"] == "test-project"
    finally
        close(server)
    end
end

@testset "GCP Metadata" begin
    request_ref = Ref{Any}()
    GCPMetadata.with(; request_ref=request_ref) do request_count
        creds = CloudBase.reloadGCECredentials!("http://127.0.0.1:50400")
        @test creds.auth isa CloudBase.GCPAccessToken
        @test creds.auth.token == "GCP_METADATA_TOKEN"
        @test request_count[] == 1
        @test request_ref[].target == "/computeMetadata/v1/instance/service-accounts/default/token"

        creds.expiration = Dates.now(Dates.UTC) - Dates.Second(1)
        @sync for _ = 1:6
            @async begin
                auth = CloudBase.getCredentials(creds)
                @test auth.token == "GCP_METADATA_TOKEN"
            end
        end
        @test request_count[] == 2
    end
end

if get(ENV, "CLOUDBASE_RUN_GCP_LIVE_TESTS", "") == "1"
@testset "GCP Live" begin
    bucket = requireenv("CLOUDBASE_GCP_LIVE_BUCKET")
    credentials = liveGCPCredentials()
    key = "cloudbase-live-$(time_ns()).txt"
    data = "cloudbase-live-$(rand(UInt))"
    url = "$(GCP.Bucket(bucket).baseurl)$key"

    put_resp = GCP.put(url, ["Content-Type" => "text/plain"], data; credentials)
    @test put_resp.status in (200, 201)

    get_resp = GCP.get(url; credentials)
    @test get_resp.status == 200
    @test String(get_resp.body) == data

    delete_resp = GCP.delete(url; credentials)
    @test delete_resp.status in (200, 202, 204)
end
end

# test debug logs are printed for azurite
@testset "Azurite debug" begin
    log = Ref{String}()
    @test_throws HTTP.StatusError Azurite.with(debug=true, debugLog=log) do conf
        credentials, container = conf
        csv = "a,b,c\n1,2,3\n4,5,$(rand())"
        # this will error since we don't have credentials
        Azure.put("$(container.baseurl)test", ["x-ms-blob-type" => "BlockBlob"], csv)
    end
    @test !isempty(log[])
end

@testset "Azurite without SSL" begin
    Azurite.with(debug=false, use_ssl=false) do conf
        credentials, container = conf
        @test startswith(container.baseurl, "http://") # instead of https://
        data = "this is a test!"
        Azure.put("$(container.baseurl)test", ["x-ms-blob-type" => "BlockBlob"], data; credentials)
        resp = Azure.get("$(container.baseurl)test"; credentials)
        @test String(resp.body) == data
    end
end

# https://github.com/JuliaServices/CloudBase.jl/issues/19
@testset "Azure SASToken idempotent" begin
    Azurite.with(debug=true) do conf
        credentials, container = conf
        csv = "a,b,c\n1,2,3\n4,5,$(rand())"
        # intentionally mess up the creds by adding "a" to the end of the query string
        creds = Azure.Credentials(string(CloudBase.generateAccountSASToken(credentials.auth.account, credentials.auth.key; signedPermission=CloudBase.SignedPermission("rw")), "a"))
        # the following will fail because we're missing x-ms-blob-type header
        ex = nothing
        try
            Azure.put("$(container.baseurl)test", ["x-ms-blob-type" => "BlockBlob"], csv; credentials=creds)
        catch e
            ex = e
        end
        params = HTTP.URIs.queryparampairs(HTTP.URI(ex.target).query)
        @test count(x -> x[1] == "sig", params) == 1
    end
end

# metrics hooks
@time @testset "Cloud metrics hooks" begin
    Minio.with(bindIP="127.0.0.1", startupDelay=0.5) do conf
        credentials, bucket = conf
        prereq_ref = Ref(0)
        metrics_ref = Ref{Any}()
        CloudBase.PREREQUEST_CALLBACK[] = (m) -> prereq_ref[] += 1
        CloudBase.METRICS_CALLBACK[] = (args...) -> metrics_ref[] = args
        csv = "a,b,c\n1,2,3\n4,5,$(rand())"
        AWS.put("$(bucket.baseurl)test.csv", [], csv; service="s3", credentials)
        @test prereq_ref[] == 1
        @test metrics_ref[] isa Tuple
        resp = AWS.get("$(bucket.baseurl)test.csv"; service="s3", credentials)
        @test String(resp.body) == csv
        @test prereq_ref[] == 2
    end
end

@testset "urlServiceRegion" begin
    @test CloudBase.urlServiceRegion("amazonaws.com") == (nothing, nothing)
    @test CloudBase.urlServiceRegion("s3.amazonaws.com") == ("s3", nothing)
    @test CloudBase.urlServiceRegion("s3.us-west-2.amazonaws.com") == ("s3", "us-west-2")
    @test CloudBase.urlServiceRegion("bucket.s3.us-west-2.amazonaws.com") == ("s3", "us-west-2")
    @test CloudBase.urlServiceRegion("bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com") == ("s3", "us-east-1")
end

@testset "redact credentials" begin
    # Make sure we don't show secrets in the output
    function test_output(creds)
        io_buffer = IOBuffer()
        Base.show(io_buffer, creds)
        str = String(take!(io_buffer))
        @test !occursin("0123456789abcdef", str)
        @test occursin("***", str)
        return nothing
    end
    test_output(CloudBase.AWSCredentials("0123456789abcdef", "0123456789abcdef", "0123456789abcdef"))
    # same for Azure
    test_output(Azure.Credentials(CloudBase.SharedKey("account_name", "0123456789abcdef")))
    test_output(Azure.Credentials(CloudBase.generateAccountSASToken("account_name", "0123456789abcdef")))
    test_output(GCP.Credentials("0123456789abcdef"))
end

@testset "_wait_for_port" begin
    port, socket = Sockets.listenany(IPv4(0), rand(RandomDevice(), 10000:50000))
    try
        _, duration = @timed CloudTest._wait_for_port("127.0.0.1", port, 1)
        @test duration < 1
    finally
        close(socket)
    end
    refused_port = 54523
    @test_throws ErrorException CloudTest._wait_for_port("127.0.0.1", refused_port, 0)

    _, duration = @timed @test_throws ErrorException CloudTest._wait_for_port("127.0.0.1", refused_port, 1)
    @test duration < 2
    # Unreachable network
    _, duration = @timed @test_throws Base.IOError CloudTest._connect_with_timeout("224.0.0.1", refused_port, 1)
    @test duration < 2
end

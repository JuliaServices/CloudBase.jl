using CloudBase, Test, CloudBase.CloudTest, JSON3, Dates, HTTP
using CloudBase: AWS, Azure
using Sockets, Random

const x32bit = Sys.WORD_SIZE == 32

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
        req = HTTP.Request(case.request.method, case.request.path, case.request.headers, case.request.body; url=HTTP.URI(case.request.uri))
        CloudBase.awssign!(req; x_amz_date=DateTime(2015, 8, 30, 12, 36), includeContentSha256=false, debug=debug, configs...)
        if i in knownFailures
            @test_broken HTTP.header(req, "Authorization") == case.authz
        else
            @test HTTP.header(req, "Authorization") == case.authz
        end
    end
end

@testset "AWSSigV2" begin
    req = HTTP.Request("GET", "/?Action=DescribeJobFlows"; url=HTTP.URI("https://elasticmapreduce.amazonaws.com?Action=DescribeJobFlows"))
    credentials = CloudBase.AWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    CloudBase.awssignv2!(req; credentials, timestamp=DateTime(2011, 10, 3, 15, 19, 30), version="2009-03-31")
    @test req.target ==
        "?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Action=DescribeJobFlows&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2011-10-03T15%3A19%3A30&Version=2009-03-31&Signature=i91nKc4PWAt0JJIdXwz9HxZCJDdiy6cf%2FMj6vPxyYIs%3D"
    req = HTTP.Request("POST", "/", [], Dict("Action" => "DescribeJobFlows"); url=HTTP.URI("https://elasticmapreduce.amazonaws.com"))
    CloudBase.awssignv2!(req; credentials, timestamp=DateTime(2011, 10, 3, 15, 19, 30), version="2009-03-31")
    @test req.body["Signature"] == "wseguMzBRgA/4/fan8ZwEa0PIF+ws4WFbTJcG1ts5RY="
end

@time @testset "AWS" begin
    config = Ref{Any}()
    Minio.with(bindIP="127.0.0.1", startupDelay=3, waitForPortTimeout=10) do conf
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
    Minio.with(bindIP="127.0.0.1", startupDelay=3, public=true) do conf
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
    Azurite.with(startupDelay=3, waitForPortTimeout=10) do conf
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
    Azurite.with(startupDelay=3, public=true) do conf
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
        @async Minio.with(bindIP="127.0.0.1", startupDelay=3) do conf
            mconfigs[i] = conf
            credentials, bucket = conf
            csv = "a,b,c\n1,2,3\n4,5,$(rand())"
            AWS.put("$(bucket.baseurl)test.csv", [], csv; service="s3", credentials)
            resp = AWS.get("$(bucket.baseurl)test.csv"; service="s3", credentials)
            @test String(resp.body) == csv
        end
        if !x32bit
            @async Azurite.with(startupDelay=3) do conf
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
    Minio.with(bindIP="127.0.0.1", startupDelay=3) do conf
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

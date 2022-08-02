using CloudBase, Test, CloudBase.CloudTest, JSON3, Dates, HTTP

@testset "AWSSigV4" begin
    file = abspath(joinpath(dirname(pathof(CloudBase)), "../test/resources/awsSig4Cases.json"))
    cases = JSON3.read(read(file))
    configs = copy(cases.config)
    configs[:access_key_id] = configs[:accessKeyId]
    delete!(configs, :accessKeyId)
    configs[:secret_access_key] = configs[:secretAccessKey]
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
    CloudBase.awssignv2!(req; access_key_id="AKIAIOSFODNN7EXAMPLE", secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", timestamp=DateTime(2011, 10, 3, 15, 19, 30), version="2009-03-31")
    @test req.target ==
        "?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Action=DescribeJobFlows&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2011-10-03T15%3A19%3A30&Version=2009-03-31&Signature=i91nKc4PWAt0JJIdXwz9HxZCJDdiy6cf%2FMj6vPxyYIs%3D"
    req = HTTP.Request("POST", "/", [], Dict("Action" => "DescribeJobFlows"); url=HTTP.URI("https://elasticmapreduce.amazonaws.com"))
    CloudBase.awssignv2!(req; access_key_id="AKIAIOSFODNN7EXAMPLE", secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", timestamp=DateTime(2011, 10, 3, 15, 19, 30), version="2009-03-31")
    @test req.body["Signature"] == "wseguMzBRgA/4/fan8ZwEa0PIF+ws4WFbTJcG1ts5RY="
end

@time @testset "AWS" begin
    config = Ref{Any}()
    Minio.with() do conf
        config[] = conf
        port, bkt, acct, secret = conf.port, conf.bucket, conf.account, conf.secret
        csv = "a,b,c\n1,2,3\n4,5,$(rand())"
        AWS.put("http://127.0.0.1:$port/$bkt/test.csv", [], csv; service="s3", access_key_id=acct, secret_access_key=secret)
        resp = AWS.get("http://127.0.0.1:$port/$bkt/test.csv"; service="s3", access_key_id=acct, secret_access_key=secret)
        @test String(resp.body) == csv
    end
    @test !isdir(config[].dir)
    @test success(config[].process)
end

@time @testset "Azure" begin
    config = Ref{Any}()
    Azurite.with() do conf
        config[] = conf
        port, bkt, acct, secret = conf.port, conf.bucket, conf.account, conf.secret
        csv = "a,b,c\n1,2,3\n4,5,$(rand())"
        Azure.put("http://127.0.0.1:$port/$acct/$bkt/test", ["x-ms-blob-type" => "BlockBlob"], csv; account=acct, key=secret)
        resp = Azure.get("http://127.0.0.1:$port/$acct/$bkt/test"; account=acct, key=secret)
        @test String(resp.body) == csv
    end
    @test !isdir(config[].dir)
    @test success(config[].process)
end

@testset "Concurrent Minio/Azurite test servers" begin
    mconfigs = Vector{Any}(undef, 10)
    aconfigs = Vector{Any}(undef, 10)
    @sync for i = 1:10
        @async Minio.with() do conf
            mconfigs[i] = conf
            port, bkt, acct, secret = conf.port, conf.bucket, conf.account, conf.secret
            csv = "a,b,c\n1,2,3\n4,5,$(rand())"
            AWS.put("http://127.0.0.1:$port/$bkt/test.csv", [], csv; service="s3", access_key_id=acct, secret_access_key=secret)
            resp = AWS.get("http://127.0.0.1:$port/$bkt/test.csv"; service="s3", access_key_id=acct, secret_access_key=secret)
            @test String(resp.body) == csv
        end
        @async Azurite.with() do conf
            aconfigs[i] = conf
            port, bkt, acct, secret = conf.port, conf.bucket, conf.account, conf.secret
            csv = "a,b,c\n1,2,3\n4,5,$(rand())"
            Azure.put("http://127.0.0.1:$port/$acct/$bkt/test", ["x-ms-blob-type" => "BlockBlob"], csv; account=acct, key=secret)
            resp = Azure.get("http://127.0.0.1:$port/$acct/$bkt/test"; account=acct, key=secret)
            @test String(resp.body) == csv
        end
    end
    for i = 1:10
        @test !isdir(mconfigs[i].dir)
        @test success(mconfigs[i].process)
        @test !isdir(aconfigs[i].dir)
        @test success(aconfigs[i].process)
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
    end
end

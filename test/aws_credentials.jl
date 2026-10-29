using Test, Dates, CloudBase, HTTP, JSON, URIs

@testset "AWS credential providers" begin
    dir = mktempdir()
    credfile = joinpath(dir, "credentials")
    configfile = joinpath(dir, "config")
    tokenfile = joinpath(dir, "web-identity-token")
    write(tokenfile, "web-identity-jwt\n")
    write(credfile, """
        [default]
        aws_access_key_id = FILE_DEFAULT_KEY
        aws_secret_access_key = FILE_DEFAULT_SECRET
        aws_session_token = FILE_DEFAULT_TOKEN

        [dev]
        aws_access_key_id = DEV_KEY
        aws_secret_access_key = DEV_SECRET

        [source]
        aws_access_key_id = SOURCE_KEY
        aws_secret_access_key = SOURCE_SECRET
        """)
    write(configfile, """
        [profile cfgonly]
        aws_access_key_id = CFG_KEY
        aws_secret_access_key = CFG_SECRET

        [profile role]
        role_arn = arn:aws:iam::123456789012:role/Admin
        source_profile = source
        """)
    # Fake STS: AssumeRole must be signed with the source keys, web identity unsigned.
    sts_calls = Channel{Any}(Inf)
    sts_status = Ref(200)
    sts = HTTP.serve!("127.0.0.1", 0) do request
        params = URIs.queryparams(String(request.body))
        action = params["Action"]
        put!(sts_calls, (action=action, role=params["RoleArn"], token=get(params, "WebIdentityToken", ""),
            authorization=HTTP.header(request, "Authorization", "")))
        sts_status[] == 200 || return HTTP.Response(sts_status[], "unavailable")
        return HTTP.Response(200, """
            <$(action)Response xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
              <$(action)Result>
                <Credentials>
                  <AccessKeyId>$(action)_KEY</AccessKeyId>
                  <SecretAccessKey>$(action)_SECRET</SecretAccessKey>
                  <SessionToken>$(action)_TOKEN</SessionToken>
                  <Expiration>2099-01-01T00:00:00Z</Expiration>
                </Credentials>
              </$(action)Result>
              <ResponseMetadata><RequestId>request-id</RequestId></ResponseMetadata>
            </$(action)Response>""")
    end
    fields(c) = (c.access_key_id, c.secret_access_key, c.session_token)
    environment = [k => nothing for k in keys(ENV) if startswith(k, "AWS_")]
    try
        withenv(environment..., "AWS_SHARED_CREDENTIALS_FILE" => credfile, "AWS_CONFIG_FILE" => configfile,
                "AWS_ENDPOINT_URL_STS" => "http://127.0.0.1:$(HTTP.port(sts))/") do
            # One provider supplies every field: env keys never pick up a file token.
            withenv("AWS_ACCESS_KEY_ID" => "ENV_KEY", "AWS_SECRET_ACCESS_KEY" => "ENV_SECRET") do
                @test fields(CloudBase.AWSCredentials()) == ("ENV_KEY", "ENV_SECRET", "")
                # An explicit profile is used even when environment keys exist.
                @test fields(CloudBase.AWSCredentials("dev")) == ("DEV_KEY", "DEV_SECRET", "")
            end
            @test fields(CloudBase.AWSCredentials()) == ("FILE_DEFAULT_KEY", "FILE_DEFAULT_SECRET", "FILE_DEFAULT_TOKEN")
            # Credentials file sections are `[name]`; config file sections are `[profile name]`.
            @test fields(CloudBase.AWSCredentials("cfgonly")) == ("CFG_KEY", "CFG_SECRET", "")
            dev = CloudBase.AWSCredentials("dev")
            @test dev.profile == "dev"
            # A reload reads the same profile again.
            dev.expiration = Dates.now(Dates.UTC) - Dates.Minute(1)
            @test CloudBase.getCredentials(dev).access_key_id == "DEV_KEY"

            role = CloudBase.AWSCredentials("role")
            @test fields(role) == ("AssumeRole_KEY", "AssumeRole_SECRET", "AssumeRole_TOKEN")
            @test role.expiration == DateTime(2099, 1, 1)
            call = take!(sts_calls)
            @test call.action == "AssumeRole"
            @test call.role == "arn:aws:iam::123456789012:role/Admin"
            @test startswith(call.authorization, "AWS4-HMAC-SHA256 Credential=SOURCE_KEY/")
            # A later load of another profile does not inherit the role.
            @test fields(CloudBase.AWSCredentials("cfgonly")) == ("CFG_KEY", "CFG_SECRET", "")
            @test !isready(sts_calls)

            withenv("AWS_ROLE_ARN" => "arn:aws:iam::123456789012:role/Web", "AWS_WEB_IDENTITY_TOKEN_FILE" => tokenfile) do
                web = CloudBase.AWSCredentials()
                @test fields(web) == ("AssumeRoleWithWebIdentity_KEY", "AssumeRoleWithWebIdentity_SECRET", "AssumeRoleWithWebIdentity_TOKEN")
                call = take!(sts_calls)
                @test call.action == "AssumeRoleWithWebIdentity"
                @test call.token == "web-identity-jwt"
                @test isempty(call.authorization)
            end

            # A failed reload keeps credentials that have not expired and raises once they have.
            sts_status[] = 500
            role.expiration = Dates.now(Dates.UTC) + Dates.Minute(2)
            @test CloudBase.getCredentials(role).access_key_id == "AssumeRole_KEY"
            role.expiration = Dates.now(Dates.UTC) - Dates.Second(1)
            @test_throws Exception CloudBase.getCredentials(role)
            sts_status[] = 200
            @test CloudBase.getCredentials(role).access_key_id == "AssumeRole_KEY"
            @test role.expiration == DateTime(2099, 1, 1)
            while isready(sts_calls)
                take!(sts_calls)
            end

            # Concurrent callers share one failed reload: STS gets one request, expired
            # credentials raise its error, and unexpired ones stay in use.
            sts_status[] = 500
            for (expiration, raises) in ((Dates.now(Dates.UTC) - Dates.Second(1), true),
                                         (Dates.now(Dates.UTC) + Dates.Minute(2), false))
                role.expiration = expiration
                ready = Channel{Nothing}(Inf)
                # Every caller waits for the lock before the first reload starts.
                tasks = lock(role.lock) do
                    tasks = [errormonitor(Threads.@spawn begin
                        put!(ready, nothing)
                        try
                            CloudBase.getCredentials(role)
                            false
                        catch err
                            err isa HTTP.StatusError
                        end
                    end) for _ in 1:40]
                    foreach(_ -> take!(ready), 1:40)
                    sleep(0.1)
                    tasks
                end
                @test all(==(raises), fetch.(tasks))
                calls = 0
                while isready(sts_calls)
                    take!(sts_calls)
                    calls += 1
                end
                @test calls == 1
            end
            sts_status[] = 200
            role.expiration = Dates.now(Dates.UTC) - Dates.Second(1)
            @test CloudBase.getCredentials(role).access_key_id == "AssumeRole_KEY"
            take!(sts_calls)

            # Concurrent loads of different profiles never mix their results.
            tasks = [errormonitor(Threads.@spawn CloudBase.AWSCredentials(isodd(i) ? "dev" : "cfgonly").access_key_id) for i in 1:20]
            @test [fetch(t) for t in tasks] == [isodd(i) ? "DEV_KEY" : "CFG_KEY" for i in 1:20]
        end
    finally
        close(sts)
    end

    # Instances that require IMDSv2 answer only requests that carry a session token.
    imds = HTTP.serve!("127.0.0.1", 0) do request
        if request.method == "PUT" && request.target == "/latest/api/token"
            return HTTP.Response(200, "imds-session")
        end
        HTTP.header(request, "X-aws-ec2-metadata-token", "") == "imds-session" || return HTTP.Response(401)
        request.target == "/latest/meta-data/iam/security-credentials/" && return HTTP.Response(200, "instance-role")
        request.target == "/latest/meta-data/placement/region" && return HTTP.Response(200, "us-west-1")
        return HTTP.Response(200, JSON.json(Dict("AccessKeyId" => "IMDS_KEY", "SecretAccessKey" => "IMDS_SECRET",
            "Token" => "IMDS_TOKEN", "Expiration" => "2099-01-01T00:00:00Z")))
    end
    try
        loaded = Dict(CloudBase.Figgy.load(CloudBase.EC2CredentialsSource("127.0.0.1", HTTP.port(imds))))
        @test loaded["aws_access_key_id"] == "IMDS_KEY"
        @test loaded["aws_session_token"] == "IMDS_TOKEN"
        @test loaded["region"] == "us-west-1"
    finally
        close(imds)
    end
end

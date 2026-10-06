using Test, Dates, CloudBase, HTTP, JSON, Sockets

@testset "Azure identity tokens" begin
    resource = "https://ossrdbms-aad.database.windows.net"
    response(token="test-access-token"; expires_in=3600, expires_on=time() + 3600) =
        HTTP.Response(200, JSON.json(Dict("access_token" => token, "token_type" => "Bearer",
            "expires_in" => expires_in, "expires_on" => expires_on)))
    mktempdir() do dir
        token_file = joinpath(dir, "assertion")
        write(token_file, "first-assertion\n")
        credentials = CloudBase.Azure.WorkloadIdentityCredentials(; resource, tenant_id="test-tenant",
            client_id="test-client", token_file)
        calls = NamedTuple[]
        request = function(method, url, headers, body; kw...)
            push!(calls, (; method, url, headers, form=Dict(HTTP.URIs.queryparampairs(HTTP.URI("http://localhost/?$body")))))
            return response()
        end
        @test isempty(calls)
        @test CloudBase.getCredentials(credentials; request).token == "test-access-token"
        @test only(calls).method == "POST"
        @test only(calls).url == "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"
        @test only(calls).form == Dict(
            "client_id" => "test-client", "scope" => resource * "/.default", "grant_type" => "client_credentials",
            "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion" => "first-assertion")
        @test ("Content-Type" => "application/x-www-form-urlencoded") in only(calls).headers
        @test CloudBase.Azure.access_token(credentials) == "test-access-token"
        @test length(calls) == 1
        @test !occursin("test-access-token", sprint(show, credentials))
        for (resource_uri, expected_scope) in (
                ("https://management.azure.com/", "https://management.azure.com//.default"),
                ("https://database.windows.net/", "https://database.windows.net//.default"))
            scoped_credentials = CloudBase.Azure.WorkloadIdentityCredentials(; resource=resource_uri,
                tenant_id="test-tenant", client_id="test-client", token_file)
            scope_request = function(method, url, headers, body; kw...)
                form = Dict(HTTP.URIs.queryparampairs(HTTP.URI("http://localhost/?$body")))
                @test form["scope"] == expected_scope
                return response()
            end
            @test CloudBase.getCredentials(scoped_credentials; request=scope_request).token == "test-access-token"
        end
        write(token_file, "rotated-assertion")
        credentials.expiration = now(UTC) + Minute(5)
        @test CloudBase.getCredentials(credentials; request).token == "test-access-token"
        @test calls[end].form["client_assertion"] == "rotated-assertion"
        @test length(calls) == 2
        credentials.expiration = now(UTC)
        concurrent_calls = Ref(0)
        concurrent_request = function(args...; kw...)
            concurrent_calls[] += 1
            sleep(0.01)
            return response("concurrent-token")
        end
        tasks = [errormonitor(Threads.@spawn CloudBase.getCredentials(credentials; request=concurrent_request).token) for _ in 1:20]
        @test all(==("concurrent-token"), fetch.(tasks))
        @test concurrent_calls[] == 1
        credentials.expiration = now(UTC)
        failure = (args...; kw...) -> throw(CloudBase.AzureIdentityError("exchange rejected"))
        @test_throws CloudBase.AzureIdentityError CloudBase.getCredentials(credentials; request=failure)
        @test credentials.auth.token == "concurrent-token"
        @test_throws CloudBase.AzureIdentityError CloudBase.getCredentials(credentials; request=(args...; kw...) -> response(; expires_in=60))
        for payload in ("[]", "not-json", JSON.json(Dict("access_token" => "", "token_type" => "Bearer", "expires_in" => 3600)),
                JSON.json(Dict("access_token" => "secret", "token_type" => "Other", "expires_in" => 3600)),
                JSON.json(Dict("access_token" => "secret", "token_type" => 42, "expires_in" => 3600)),
                JSON.json(Dict("access_token" => "secret", "token_type" => "Bearer", "expires_in" => -1)),
                JSON.json(Dict("access_token" => "secret", "token_type" => "Bearer", "expires_in" => "NaN")),
                JSON.json(Dict("access_token" => "secret", "token_type" => "Bearer")))
            err = try
                CloudBase.getCredentials(credentials; request=(args...; kw...) -> HTTP.Response(200, payload))
                nothing
            catch err
                @test length(current_exceptions()) == 1
                err
            end
            @test err isa CloudBase.AzureIdentityError
            @test !occursin("secret", sprint(showerror, err))
        end
        write(token_file, "")
        @test_throws CloudBase.AzureIdentityError CloudBase.getCredentials(credentials; request)
        rm(token_file)
        @test_throws CloudBase.AzureIdentityError CloudBase.getCredentials(credentials; request)
        withenv("AZURE_CLIENT_ID" => "env-client", "AZURE_TENANT_ID" => "env-tenant", "AZURE_FEDERATED_TOKEN_FILE" => token_file) do
            env_credentials = CloudBase.Azure.WorkloadIdentityCredentials(; resource)
            @test env_credentials.source.client_id == "env-client"
            @test env_credentials.source.token_file == token_file
        end
    end
    @test_throws ArgumentError CloudBase.Azure.WorkloadIdentityCredentials(; resource, tenant_id="", client_id="client", token_file="file")
    @test_throws ArgumentError CloudBase.Azure.WorkloadIdentityCredentials(; resource, tenant_id="tenant", client_id="", token_file="file")
    @test_throws ArgumentError CloudBase.Azure.WorkloadIdentityCredentials(; resource, tenant_id="tenant", client_id="client", token_file="")
    for authority_host in ("http://login.microsoftonline.com/", "https://login.microsoftonline.com/token", "https://user:pass@host/", "https://host/?token=secret")
        @test_throws ArgumentError CloudBase.Azure.WorkloadIdentityCredentials(; resource, tenant_id="tenant", client_id="client", token_file="file", authority_host)
    end
    @test_throws ArgumentError CloudBase.Azure.ManagedIdentityCredentials(; resource="http://example.com")
    @test_throws ArgumentError CloudBase.Azure.ManagedIdentityCredentials(; resource, expireThreshold=Second(-1))
    @test_throws ArgumentError CloudBase.Azure.ManagedIdentityCredentials(; resource, endpoint="http://untrusted.example/token")
    calls = Ref(0)
    server = HTTP.serve!("127.0.0.1", 0) do request
        calls[] += 1
        @test HTTP.header(request.headers, "Metadata") == "true"
        query = Dict(HTTP.URIs.queryparampairs(HTTP.URI("http://localhost" * request.target)))
        @test query["resource"] == resource
        @test query["api-version"] == "2018-02-01"
        @test query["client_id"] == "selected-client"
        return response(; expires_on=string(floor(Int, time() + 3600)))
    end
    try
        port = HTTP.port(server)
        credentials = CloudBase.Azure.ManagedIdentityCredentials(; resource, client_id="selected-client",
            endpoint="http://127.0.0.1:$port/metadata/identity/oauth2/token")
        @test CloudBase.Azure.access_token(credentials) == "test-access-token"
        @test CloudBase.Azure.access_token(credentials) == "test-access-token"
        @test calls[] == 1
        credentials.expiration = now(UTC)
        @test_throws CloudBase.AzureIdentityError CloudBase.getCredentials(credentials; request=(args...; kw...) -> response(; expires_on=time() - 1))
    finally
        close(server)
    end
    redirects = Ref(0)
    server = HTTP.serve!("127.0.0.1", 0) do request
        redirects[] += 1
        return HTTP.Response(302, ["Location" => "/leak"], "private-error-body")
    end
    try
        port = HTTP.port(server)
        err = try
            CloudBase.azureIdentityRequest("GET", "http://127.0.0.1:$port/token", Pair{String,String}[])
            nothing
        catch err
            err
        end
        @test err isa CloudBase.AzureIdentityError
        @test occursin("HTTP 302", sprint(showerror, err))
        @test !occursin("private-error-body", sprint(showerror, err))
        @test redirects[] == 1
    finally
        close(server)
    end
end

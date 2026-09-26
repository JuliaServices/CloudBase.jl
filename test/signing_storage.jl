@testset "Signing borrows unread payload storage" begin
    creds = AWS.Credentials("example-key", "example-secret")
    url = HTTP.URI("https://bucket.s3.us-east-1.amazonaws.com/object")
    sign(req) = CloudBase.awssign!(req, url; credentials=creds, x_amz_date=DateTime(2026, 9, 21))
    allocations = Int[]
    for n in (1024, 1 << 20)
        data = fill(0x61, n)
        req = HTTP.Request("PUT", "/object"; body=data)
        @test CloudBase.requestbodybytes(req) === data
        @test minimum(@allocated(CloudBase.requestbodybytes(req)) for _ in 1:5) < 1024
        sign(req)
        push!(allocations, minimum(@allocated(sign(req)) for _ in 1:5))
        for offset in (1, 3, n + 1)
            empty!(req.headers)
            req.body.next_index = offset
            expected = HTTP.Request("PUT", "/object"; body=copy(@view data[offset:end]))
            req.content_length = length(expected.body)
            sign(expected)
            sign(req)
            @test HTTP.header(req, "Authorization") == HTTP.header(expected, "Authorization")
            @test HTTP.header(req, "X-Amz-Content-Sha256") == HTTP.header(expected, "X-Amz-Content-Sha256")
            @test req.body.next_index == offset
            @test all(==(0x61), data)
        end
    end
    # Fixed signing overhead varies with compiler and logging state; payload
    # growth must not add another body-sized allocation.
    @test allocations[2] <= allocations[1] + 4096
end

@testset "Signing uses complete final headers" begin
    credentials = AWS.Credentials("fixture-key", "fixture-secret")
    url = HTTP.URI("https://s3.us-east-1.amazonaws.com/bucket/key")
    sign(req; kw...) = CloudBase.awssign!(req, url; credentials,
        x_amz_date=DateTime(2026, 9, 26), kw...)
    data = collect(codeunits("body"))
    fresh = HTTP.Request("PUT", "/bucket/key"; body=data)
    sign(fresh)
    @test occursin("SignedHeaders=host;x-amz-content-sha256;x-amz-date,", HTTP.header(fresh, "Authorization"))
    for value in ("stale", bytes2hex(CloudBase.sha256(data)), "")
        request = HTTP.Request("PUT", "/bucket/key"; body=data,
            headers=["x-amz-content-sha256" => value])
        sign(request)
        @test HTTP.header(request, "Authorization") == HTTP.header(fresh, "Authorization")
        @test CloudBase.requestbodybytes(request) === data
    end
    data[1] = 0x42
    sign(fresh)
    expected = HTTP.Request("PUT", "/bucket/key"; body=data)
    sign(expected)
    @test HTTP.header(fresh, "Authorization") == HTTP.header(expected, "Authorization")
    @test fresh.body.next_index == 1

    omitted = HTTP.Request("PUT", "/bucket/key"; body=data)
    sign(omitted; includeContentSha256=false)
    @test !HTTP.hasheader(omitted, "x-amz-content-sha256")
    supplied = HTTP.Request("PUT", "/bucket/key"; body=data,
        headers=["x-amz-content-sha256" => "caller-value"])
    sign(supplied; includeContentSha256=false)
    @test HTTP.header(supplied, "x-amz-content-sha256") == "caller-value"

    for (input, canonical) in (
        ["X" => ""] => ["x" => ""],
        ["X" => "", "x" => ""] => ["x" => ","],
        ["X" => "", "x" => " a\t  b ", "Y" => ""] => ["x" => ",a b", "y" => ""],
        ["X" => "a", "X" => "", "X" => "b"] => ["x" => "a,,b"],
        ["X" => " a\tb\t\tc "] => ["x" => "a b c"],
    )
        headers = map(CloudBase.canonicalHeader, input)
        @test CloudBase.deduplicateHeaders!(headers) === nothing
        @test headers == canonical
    end
    request = HTTP.Request("PUT", "/bucket/key"; body=data,
        headers=["x-amz-meta-empty" => ""])
    sign(request)
    @test occursin(";x-amz-meta-empty,", HTTP.header(request, "Authorization"))
end

@testset "S3 verifies generated hashes and metadata headers" begin
    Minio.with() do conf
        credentials, bucket = conf
        for headers in (
            ["x-amz-content-sha256" => bytes2hex(CloudBase.sha256("old body"))],
            ["x-amz-meta-space" => "a\t  b"],
            ["x-amz-meta-empty" => ""],
        )
            response = AWS.put(bucket.baseurl * "/headers", headers, "body";
                credentials, service="s3", region="us-east-1", retries=0)
            @test response.status == 200
        end
    end
end

@testset "Explicit clients own TLS policy" begin
    client = HTTP.Client()
    try
        kw = CloudBase.cloudhttpkwargs(:azure, HTTP.URI("https://127.0.0.1/blob"), nothing, (; client))
        @test !haskey(kw, :require_ssl_verification)
    finally
        close(client)
    end
end

@testset "String-backed payload hashing" begin
    # Include byte ranges that split a UTF-8 character: signing treats bytes,
    # not text. Hashing must preserve the owner and work through forced GC.
    text = repeat("aα", 10000)
    for input in (codeunits(text), codeunits(SubString(text, 2)),
            view(codeunits(text), 3:ncodeunits(text)-1), view(codeunits(text), 1:0))
        expected = CloudBase.sha256(Vector{UInt8}(input))
        @test CloudBase.payloadsha256(input) == expected
        GC.gc()
        @test CloudBase.payloadsha256(input) == expected
        @test minimum(@allocated(CloudBase.payloadsha256(input)) for _ in 1:5) < 4096
    end
end

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

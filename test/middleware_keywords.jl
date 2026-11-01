@testset "Cloud middleware separates signer and HTTP keywords" begin
    url = "https://fixture.example/bucket/object"
    credentials = AWS.Credentials("example-key", "example-secret")
    timestamp = DateTime(2026, 10, 30)
    signing = (; service="s3", region="us-west-2", x_amz_date=timestamp,
        includeContentSha256=true, debug=false, version="unused", timestamp,
        addMd5=false)
    forwarded = (; retries=0, read_idle_timeout=17, proxy=nothing)
    seen = Ref(0)
    trace = _ -> (seen[] += 1)

    request_handler = function(method, url, headers, body; trace, kw...)
        request = HTTP.Request(method, HTTP.URI(url).path; headers, body)
        trace(HTTP.RequestEvent(request, url, 1, 0, :h1))
        return request, (; kw...)
    end
    request = CloudBase.cloudlayer(:aws)(request_handler)
    signed, httpkw = request("PUT", url, Pair{String,String}[], "body";
        credentials, trace, signing..., forwarded...)
    @test httpkw == forwarded
    @test seen[] == 1
    @test HTTP.header(signed, "x-amz-date") == "20261030T000000Z"
    @test occursin("/us-west-2/s3/aws4_request", HTTP.header(signed, "Authorization"))
    @test HTTP.header(signed, "x-amz-content-sha256") == bytes2hex(CloudBase.sha256("body"))

    open_handler = (method, url, headers; kw...) -> (headers, (; kw...))
    open = CloudBase.cloudopenlayer(:aws)(open_handler)
    headers, httpkw = open("GET", url; credentials, signing..., forwarded...)
    @test httpkw == merge((; redirect=false), forwarded)
    @test HTTP.header(HTTP.Headers(headers), "x-amz-date") == "20261030T000000Z"
    @test occursin("/us-west-2/s3/aws4_request", HTTP.header(HTTP.Headers(headers), "Authorization"))

    # Both empty and HTTP-only keyword sets retain the default read timeout.
    plain = CloudBase.cloudopenlayer(:azure)(open_handler)
    @test last(plain("GET", url)) == (; read_idle_timeout=300)
    @test last(plain("GET", url; retries=0)) == (; read_idle_timeout=300, retries=0)
end

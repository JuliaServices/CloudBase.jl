using Documenter, CloudBase

makedocs(;
    pages=[
        "Home" => "index.md",
        "API Reference" => "reference.md",
    ],
    sitename="CloudBase.jl",
)

deploydocs(;
    repo="github.com/JuliaServices/CloudBase.jl",
    devbranch = "main",
    push_preview = true,
)

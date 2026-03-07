using Pkg

Pkg.develop(PackageSpec(path=joinpath(@__DIR__, "..")))

using Documenter, CloudBase
const GCP = getfield(CloudBase, :GCP)
const reloadGCECredentials! = getfield(CloudBase, :reloadGCECredentials!)

makedocs(;
    modules=[CloudBase],
    warnonly=[:missing_docs],
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

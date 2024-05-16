module github.com/manifestori/sbom-composer/parser

go 1.22

require (
	github.com/spdx/tools-golang v0.5.4
	github.com/stretchr/testify v1.9.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/anchore/go-struct-converter v0.0.0-20221118182256-c68fdcfa2092 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
)

replace github.com/spdx/tools-golang => github.com/manifestori/tools-golang v0.0.0-20240516165255-7ab49e4f1c20

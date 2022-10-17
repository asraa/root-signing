module github.com/asraa/test-sigstore-root

go 1.16

require (
	github.com/peterbourgon/ff/v3 v3.1.2
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.13.1
	github.com/sigstore/sigstore v1.4.4
	github.com/spf13/cobra v1.6.0
	github.com/spf13/viper v1.13.0
	github.com/tent/canonical-json-go v0.0.0-20130607151641-96e4ba3a7613
	github.com/theupdateframework/go-tuf v0.5.2-0.20220930112810-3890c1e7ace4
	golang.org/x/term v0.0.0-20220919170432-7a66f970e087
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/theupdateframework/go-tuf => github.com/mnm678/go-tuf v0.0.0-20220304223310-cbf366a5642a

module github.com/trknhr/envvault/examples/microsandbox

go 1.25.0

require github.com/superradcompany/microsandbox/sdk/go v0.7.13

require github.com/trknhr/envvault v0.0.0

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/zalando/go-keyring v0.2.8 // indirect
	golang.org/x/sys v0.44.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/trknhr/envvault => ../..

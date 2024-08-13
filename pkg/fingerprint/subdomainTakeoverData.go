package fingerprint

import (
	_ "embed"
)

//go:embed dicts/subdomainFinger.json
var subdomainFinger string

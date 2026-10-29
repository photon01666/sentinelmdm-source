//go:build arm64

package embedded

import _ "embed"

//go:embed xray-arm64
var XrayBinary []byte

const XrayVersion = "26.3.27"

package util

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// fieldSeparator mirrors the TS impl: a unit-separator byte (0x1F).
const fieldSeparator = "\x1f"

// EncodeID encodes an arbitrary UTF-8 string as a URL-safe base64 id.
func EncodeID(input string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(input))
}

// DecodeID decodes a base64url id back into its composite key.
func DecodeID(id string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// BuildVulnerabilityKey builds the stable composite key for one vulnerability
// occurrence.
func BuildVulnerabilityKey(target, vulnerabilityID, pkgName string, installedVersion *string) string {
	iv := ""
	if installedVersion != nil {
		iv = *installedVersion
	}
	return target + fieldSeparator + vulnerabilityID + fieldSeparator + pkgName + fieldSeparator + iv
}

// BuildFindingID builds a stable base64url id for a non-vulnerability finding.
// parts may contain strings, ints, or nil; nil is rendered as "".
func BuildFindingID(parts []interface{}) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += fieldSeparator
		}
		switch v := p.(type) {
		case nil:
			out += ""
		case string:
			out += v
		case int:
			out += fmt.Sprintf("%d", v)
		case int64:
			out += fmt.Sprintf("%d", v)
		case float64:
			out += fmt.Sprintf("%v", v)
		case bool:
			if v {
				out += "true"
			} else {
				out += "false"
			}
		default:
			out += fmt.Sprintf("%v", v)
		}
	}
	return EncodeID(out)
}

// GenerateScanID produces a fresh opaque id for a scan record when no slot id
// is supplied. Mirrors encodeId(`scan:${artifactName}:${ts}:${rand}`).
func GenerateScanID(artifactName string) string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return EncodeID(fmt.Sprintf("scan:%s:%d:%x", artifactName, time.Now().UnixMilli(), buf[:]))
}

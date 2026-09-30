package parser

// raw_types.go contains loose shape aliases for untrusted Trivy JSON input.
// Real Trivy reports vary across versions, so every accessor goes through
// defensive helpers in trivy.go (AsStr, AsNum, ToObj, ...). We never
// unmarshal directly into a typed struct — every report is parsed into a
// generic map[string]interface{} tree and walked defensively.

// Report is the (loose) shape of the top-level Trivy JSON document.
// We only declare fields we explicitly walk; everything else stays dynamic.
type Report struct {
	SchemaVersion interface{} `json:"SchemaVersion,omitempty"`
	ArtifactName  interface{} `json:"ArtifactName,omitempty"`
	ArtifactType  interface{} `json:"ArtifactType,omitempty"`
	Metadata      interface{} `json:"Metadata,omitempty"`
	Results       interface{} `json:"Results,omitempty"`
	Scanners      interface{} `json:"Scanners,omitempty"`
}

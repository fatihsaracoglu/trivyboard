package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// DockerImage is the trimmed image record returned by GET /api/docker/images.
type DockerImage struct {
	ID          string            `json:"id"`
	RepoTags    []string          `json:"repoTags"`
	RepoDigests []string          `json:"repoDigests"`
	Created     int64             `json:"created"`
	Size        int64             `json:"size"`
	Digest      string            `json:"digest"`
	ShortID     string            `json:"shortId"`
	Labels      map[string]string `json:"labels"`
	OS          string            `json:"os"`
	Arch        string            `json:"arch"`
}

// DockerImagesResult is the response envelope returned by the images endpoint.
// Source values:
//   - "docker"       — daemon reachable, real images returned
//   - "unavailable"  — daemon not reachable (socket not found / connection refused)
//   - "empty"        — daemon reachable but no images present
type DockerImagesResult struct {
	Data   []DockerImage `json:"data"`
	Source string        `json:"source"`
}

// ListDockerImages queries the local Docker Engine API over the unix socket
// for the image list. If the daemon is unreachable, returns source="unavailable".
// If reachable but no images, returns source="empty".
func ListDockerImages(socketPath string) DockerImagesResult {
	// First check if the daemon is reachable at all.
	if !isDockerReachable(socketPath) {
		return DockerImagesResult{Data: []DockerImage{}, Source: "unavailable"}
	}

	images, err := queryDockerImages(socketPath)
	if err != nil {
		return DockerImagesResult{Data: []DockerImage{}, Source: "unavailable"}
	}
	if len(images) == 0 {
		return DockerImagesResult{Data: []DockerImage{}, Source: "empty"}
	}
	return DockerImagesResult{Data: images, Source: "docker"}
}

// isDockerReachable returns true if the Docker unix socket exists and accepts
// a TCP-style connection within 2 seconds.
func isDockerReachable(socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func queryDockerImages(socketPath string) ([]DockerImage, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
	req, err := http.NewRequest("GET", "http://docker/v1.41/images/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docker daemon returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	images := make([]DockerImage, 0, len(raw))
	for _, r := range raw {
		images = append(images, parseDockerImage(r))
	}
	return images, nil
}

// parseDockerImage defensively extracts the fields we expose from one element
// of the Docker Engine `/images/json` array.
func parseDockerImage(r map[string]interface{}) DockerImage {
	id := asString(r["Id"])
	shortID := id
	if len(shortID) > 19 {
		if i := lastIndex(shortID, ':'); i >= 0 && len(shortID)-i > 13 {
			shortID = shortID[:i+1+12]
		}
	}
	created := asInt64(r["Created"])
	size := asInt64(r["Size"])
	labels := map[string]string{}
	if l, ok := r["Labels"].(map[string]interface{}); ok {
		for k, v := range l {
			if s, ok := v.(string); ok {
				labels[k] = s
			}
		}
	}
	os := asString(r["Os"])
	arch := asString(r["Architecture"])
	digest := asString(r["Digest"])
	return DockerImage{
		ID:          id,
		RepoTags:    asStringSlice(r["RepoTags"]),
		RepoDigests: asStringSlice(r["RepoDigests"]),
		Created:     created,
		Size:        size,
		Digest:      digest,
		ShortID:     shortID,
		Labels:      labels,
		OS:          os,
		Arch:        arch,
	}
}

func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asInt64(v interface{}) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int:
		return int64(n)
	case int64:
		return n
	}
	return 0
}

func asStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func lastIndex(s string, ch byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ch {
			return i
		}
	}
	return -1
}

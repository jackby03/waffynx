package parsers

import (
	"fmt"
	"net/http"
	"strings"
)

type FileUploadResult struct {
	IsUpload      bool     `json:"is_upload"`
	ContentType   string   `json:"content_type"`
	Extension     string   `json:"extension,omitempty"`
	Size          int      `json:"size"`
	IsExecutable  bool     `json:"is_executable"`
	MagicMatch    bool     `json:"magic_match"`
	Issues        []string `json:"issues,omitempty"`
}

var blockedExtensions = []string{
	".exe", ".dll", ".so", ".dylib", ".sh", ".bash",
	".php", ".jsp", ".asp", ".aspx", ".cgi", ".pl", ".py", ".rb",
	".war", ".jar", ".class",
}

var blockedContentTypes = []string{
	"application/x-msdownload",
	"application/x-msdos-program",
	"application/x-msi",
	"application/x-sh",
	"application/x-shockwave-flash",
}

var magicSignatures = map[string][]byte{
	"image/jpeg":        {0xFF, 0xD8, 0xFF},
	"image/png":         {0x89, 0x50, 0x4E, 0x47},
	"image/gif":         {0x47, 0x49, 0x46},
	"application/pdf":   {0x25, 0x50, 0x44, 0x46},
	"application/zip":   {0x50, 0x4B, 0x03, 0x04},
	"application/x-gzip": {0x1F, 0x8B},
	"audio/mpeg":        {0xFF, 0xFB},
}

func InspectFileUpload(r *http.Request, body []byte) *FileUploadResult {
	result := &FileUploadResult{
		ContentType: r.Header.Get("Content-Type"),
		Size:        len(body),
	}

	isMultipart := strings.HasPrefix(result.ContentType, "multipart/form-data")
	_ = isMultipart

	if !isUpload(result.ContentType, body) {
		return result
	}

	result.IsUpload = true

	for _, ext := range blockedExtensions {
		if strings.HasSuffix(strings.ToLower(r.URL.Path), ext) {
			result.Extension = ext
			result.Issues = append(result.Issues, fmt.Sprintf("blocked extension: %s", ext))
			break
		}
	}

	for _, ct := range blockedContentTypes {
		if strings.Contains(strings.ToLower(result.ContentType), ct) {
			result.Issues = append(result.Issues, fmt.Sprintf("blocked content type: %s", ct))
			result.IsExecutable = true
			break
		}
	}

	result.MagicMatch = validateMagicBytes(result.ContentType, body)
	if !result.MagicMatch && len(body) > 4 {
		result.Issues = append(result.Issues, "content-type does not match file signature")
	}

	if result.Size > 50*1024*1024 {
		result.Issues = append(result.Issues, "file size exceeds limit (50MB)")
	}

	return result
}

func isUpload(contentType string, body []byte) bool {
	if strings.HasPrefix(contentType, "multipart/form-data") {
		return true
	}
	if len(body) > 0 {
		ct := strings.ToLower(contentType)
		uploadCTs := []string{"image/", "application/octet-stream", "application/pdf", "application/zip"}
		for _, prefix := range uploadCTs {
			if strings.HasPrefix(ct, prefix) {
				return true
			}
		}
	}
	return false
}

func validateMagicBytes(contentType string, data []byte) bool {
	if len(data) < 4 {
		return true
	}

	for ct, magic := range magicSignatures {
		if strings.HasPrefix(strings.ToLower(contentType), ct) {
			if len(magic) > len(data) {
				return false
			}
			for i, b := range magic {
				if data[i] != b {
					return false
				}
			}
			return true
		}
	}

	return true
}

package parsers

import (
	"net/http"
	"testing"
)

func FuzzInspectGraphQL(f *testing.F) {
	f.Add([]byte(`{"query":"{ users { id name } }"}`))
	f.Add([]byte(`{"query":"{ __schema { types { name } } }"}`))
	f.Add([]byte(`[{"query":"{ users { id } }"},{"query":"{ posts { title } }"}]`))
	f.Add([]byte(`{"user":"admin","pass":"secret"}`))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		InspectGraphQL("application/json", data)
		InspectGraphQL("application/graphql", data)
		InspectGraphQL("text/plain", data)
	})
}

func FuzzInspectFileUpload(f *testing.F) {
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0x00, 0x00, 0x00})
	f.Add([]byte("<?php echo 'hi'; ?>"))
	f.Add([]byte("this is not a JPEG file!"))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		r, _ := http.NewRequest("POST", "/upload/file.jpg", nil)
		r.Header.Set("Content-Type", "image/jpeg")
		InspectFileUpload(r, data)
		
		r2, _ := http.NewRequest("POST", "/upload/shell.php", nil)
		r2.Header.Set("Content-Type", "multipart/form-data")
		InspectFileUpload(r2, data)
	})
}

with open("./internal/api/middleware.go", "r") as f:
    content = f.read()

content = content.replace(
"""func (s *Server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {""",
"""func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {"""
)

content = content.replace(
"""		if r.Method == http.MethodOptions {
			if allowedOrigin != "" {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		next(w, r)
	}
}""",
"""		if r.Method == http.MethodOptions {
			if allowedOrigin != "" {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}"""
)

with open("./internal/api/middleware.go", "w") as f:
    f.write(content)

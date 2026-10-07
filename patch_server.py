with open("./internal/api/server.go", "r") as f:
    content = f.read()

content = content.replace(
"""// Handler compiles and returns the HTTP handler with all registered routes and middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	return s.auditMiddleware(s.loggingMiddleware(mux))
}""",
"""// Handler compiles and returns the HTTP handler with all registered routes and middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	return s.corsMiddleware(s.auditMiddleware(s.loggingMiddleware(mux)))
}"""
)

with open("./internal/api/server.go", "w") as f:
    f.write(content)

with open("./internal/api/middleware.go", "r") as f:
    content = f.read()

content = content.replace(
"""		start := time.Now()
		next(w, r)
		logging.Debug().""",
"""		start := time.Now()
		next.ServeHTTP(w, r)
		logging.Debug()."""
)

with open("./internal/api/middleware.go", "w") as f:
    f.write(content)

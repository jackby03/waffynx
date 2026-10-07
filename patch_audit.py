with open("./internal/api/middleware.go", "r") as f:
    content = f.read()

content = content.replace(
"""		if s.audit == nil {
			next(w, r)
			return
		}""",
"""		if s.audit == nil {
			next.ServeHTTP(w, r)
			return
		}"""
)

with open("./internal/api/middleware.go", "w") as f:
    f.write(content)

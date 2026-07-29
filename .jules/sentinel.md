## 2024-05-XX - Weak Default JWT Secret Allowed
* **Title:** Weak Default JWT Secret Allowed
* **Vulnerability:** The API server only logged a warning if the JWT secret was empty or set to a specific default literal ("change-me-in-production"), allowing it to start with weak/default credentials.
* **Learning:** Always enforce strong security defaults. Fail-safe design means applications should refuse to start if critical security configurations (like signing keys) are missing or known to be insecure, rather than just warning the user.
* **Prevention:** Implement strict length and complexity checks for sensitive configuration values during application startup and exit with an error if they are not met (e.g., require at least 32 bytes for HS256 JWT keys).

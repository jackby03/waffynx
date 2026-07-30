## 2024-05-XX - Weak Default JWT Secret Allowed
* **Title:** Weak Default JWT Secret Allowed
* **Vulnerability:** The API server only logged a warning if the JWT secret was empty or set to a specific default literal ("change-me-in-production"), allowing it to start with weak/default credentials.
* **Learning:** Always enforce strong security defaults. Fail-safe design means applications should refuse to start if critical security configurations (like signing keys) are missing or known to be insecure, rather than just warning the user.
* **Prevention:** Implement strict length and complexity checks for sensitive configuration values during application startup and exit with an error if they are not met (e.g., require at least 32 bytes for HS256 JWT keys).

## 2024-05-XX - Weak Default API Key Allowed
**Vulnerability:** The agent server only logged a warning if the API key was set to a specific default literal ("change-me-in-production") or empty, allowing it to start with weak/default credentials.
**Learning:** Failing to strictly validate API keys at startup can lead to unauthorized access to critical endpoints (like firewall control).
**Prevention:** Always abort server startup if required security credentials (like API keys or JWT secrets) are empty or match known unsafe default values.

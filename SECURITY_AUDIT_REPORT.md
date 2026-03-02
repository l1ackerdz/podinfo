# Security Audit Report — podinfo

**Date:** 2026-03-02  
**Scope:** Full codebase audit — Go HTTP/gRPC microservice  
**Severity Levels:** 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🔵 LOW | ℹ️ INFO

---

## 1. UNAUTHENTICATED ENDPOINTS

**Every single HTTP endpoint is unauthenticated.** There is no authentication middleware applied globally. The only endpoint that checks for a token is `/token/validate`, and that is the validation endpoint itself — not a protected resource.

### HTTP Endpoints (all unauthenticated)

| Endpoint | Method(s) | Handler | Risk |
|---|---|---|---|
| `/` | GET | `indexHandler` | LOW |
| `/version` | GET | `versionHandler` | LOW |
| `/echo` | ALL | `echoHandler` | 🟠 HIGH (SSRF) |
| `/echo/{path}` | ALL | `echoHandler` | 🟠 HIGH (SSRF) |
| `/api/echo` | ALL | `echoHandler` | 🟠 HIGH (SSRF) |
| `/api/echo/{path}` | ALL | `echoHandler` | 🟠 HIGH (SSRF) |
| `/env` | GET, POST | `envHandler` | 🔴 CRITICAL |
| `/headers` | GET, POST | `echoHeadersHandler` | 🔵 LOW |
| `/delay/{wait}` | GET | `delayHandler` | 🟡 MEDIUM (DoS) |
| `/healthz` | GET | `healthzHandler` | ℹ️ INFO |
| `/readyz` | GET | `readyzHandler` | ℹ️ INFO |
| `/readyz/enable` | POST | `enableReadyHandler` | 🟠 HIGH |
| `/readyz/disable` | POST | `disableReadyHandler` | 🟠 HIGH |
| `/panic` | GET | `panicHandler` | 🔴 CRITICAL |
| `/status/{code}` | GET, POST, PUT | `statusHandler` | 🔵 LOW |
| `/store` | POST, PUT | `storeWriteHandler` | 🟠 HIGH (LFI write) |
| `/store/{hash}` | GET | `storeReadHandler` | 🟠 HIGH (LFI read) |
| `/cache/{key}` | POST, PUT | `cacheWriteHandler` | 🟡 MEDIUM |
| `/cache/{key}` | DELETE | `cacheDeleteHandler` | 🟡 MEDIUM |
| `/cache/{key}` | GET | `cacheReadHandler` | 🟡 MEDIUM |
| `/configs` | GET | `configReadHandler` | 🟠 HIGH |
| `/token` | POST | `tokenGenerateHandler` | 🟠 HIGH |
| `/token/validate` | GET | `tokenValidateHandler` | ℹ️ INFO |
| `/api/info` | GET | `infoHandler` | 🔵 LOW |
| `/ws/echo` | WS | `echoWsHandler` | 🟡 MEDIUM |
| `/chunked` | ALL | `chunkedHandler` | 🟡 MEDIUM (DoS) |
| `/chunked/{wait}` | ALL | `chunkedHandler` | 🟡 MEDIUM (DoS) |
| `/metrics` | GET | Prometheus | 🟡 MEDIUM |
| `/debug/pprof/` | ALL | pprof | 🔴 CRITICAL |
| `/swagger/` | GET | Swagger UI | 🔵 LOW |
| `/swagger.json` | GET | Swagger doc | 🔵 LOW |

### gRPC Services (all unauthenticated — no interceptors)

| Service | Method | Risk |
|---|---|---|
| `EchoService` | `Echo` | 🟡 MEDIUM |
| `VersionService` | `Version` | ℹ️ INFO |
| `PanicService` | `Panic` | 🔴 CRITICAL |
| `DelayService` | `Delay` | 🟡 MEDIUM (DoS) |
| `HeaderService` | `Header` | 🔵 LOW |
| `InfoService` | `Info` | 🔵 LOW |
| `StatusService` | `Status` | 🔵 LOW |
| `TokenService` | `TokenGenerate` | 🟠 HIGH |
| `TokenService` | `TokenValidate` | ℹ️ INFO |
| `EnvService` | `Env` | 🔴 CRITICAL |

---

## 2. VULNERABILITY FINDINGS

---

### 🔴 VULN-001 — CRITICAL: Unauthenticated `/panic` Endpoint (DoS / Process Kill)

**File:** [`pkg/api/http/panic.go:13`](pkg/api/http/panic.go:13)  
**Type:** Denial of Service / Unauthorized Process Termination

```go
func (s *Server) panicHandler(w http.ResponseWriter, r *http.Request) {
    s.logger.Info("Panic command received")
    os.Exit(255)  // ← kills the process immediately
}
```

**Impact:** Any unauthenticated HTTP GET to `/panic` immediately terminates the server process with exit code 255. In Kubernetes, this triggers a pod restart. An attacker can continuously crash the service causing a persistent DoS.

**Same issue in gRPC:** [`pkg/api/grpc/panic.go:18`](pkg/api/grpc/panic.go:18) — `PanicService.Panic()` calls `os.Exit(225)` with no authentication.

**Remediation:** Require authentication/authorization before allowing this endpoint. Consider removing it entirely from production builds.

---

### 🔴 VULN-002 — CRITICAL: Unauthenticated `/env` Exposes All Environment Variables

**File:** [`pkg/api/http/env.go:17`](pkg/api/http/env.go:17)  
**Type:** Sensitive Data Exposure / Information Disclosure

```go
func (s *Server) envHandler(w http.ResponseWriter, r *http.Request) {
    s.JSONResponse(w, r, os.Environ())  // ← dumps ALL env vars
}
```

**Impact:** Returns the complete list of environment variables to any unauthenticated caller. In containerized environments, this commonly includes:
- Database passwords (`DB_PASSWORD`, `POSTGRES_PASSWORD`)
- API keys and secrets (`AWS_SECRET_ACCESS_KEY`, `STRIPE_SECRET_KEY`)
- JWT secrets (`PODINFO_JWT_SECRET`)
- Service account tokens
- Redis/cache credentials

**Same issue in gRPC:** [`pkg/api/grpc/env.go:17`](pkg/api/grpc/env.go:17) — `EnvService.Env()` returns `os.Environ()` with no authentication.

**Remediation:** Remove this endpoint or protect it with strong authentication. Never expose environment variables over an API.

---

### 🔴 VULN-003 — CRITICAL: pprof Debug Endpoints Exposed Without Authentication

**File:** [`pkg/api/http/server.go:98`](pkg/api/http/server.go:98)  
**Type:** Information Disclosure / Memory Dump / CPU Profiling

```go
s.router.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
```

**Impact:** The Go `net/http/pprof` package is imported and all debug endpoints are exposed:
- `/debug/pprof/heap` — full heap memory dump (may contain secrets, tokens, keys)
- `/debug/pprof/goroutine` — goroutine stack traces
- `/debug/pprof/profile` — CPU profiling (causes 30s CPU spike = DoS)
- `/debug/pprof/trace` — execution trace
- `/debug/pprof/cmdline` — process command line arguments

An attacker can dump heap memory to extract JWT secrets, Redis passwords, and other in-memory sensitive data.

**Remediation:** Move pprof to a separate internal-only port, or protect with authentication. Never expose pprof on a public-facing port.

---

### 🔴 VULN-004 — CRITICAL: Hardcoded Default JWT Secret

**File:** [`cmd/podinfo/main.go:78`](cmd/podinfo/main.go:78)  
**Type:** Weak Cryptographic Secret / Authentication Bypass

```go
viper.SetDefault("jwt-secret", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
```

**Impact:** The default JWT secret is a well-known, publicly visible string (it's literally the header of a JWT token). If the operator does not override `PODINFO_JWT_SECRET`, any attacker who knows this default can:
1. Forge valid JWT tokens for any user
2. Bypass the `/token/validate` endpoint
3. Impersonate any identity

The secret is also used in gRPC [`pkg/api/grpc/token.go:42`](pkg/api/grpc/token.go:42).

**Remediation:** Remove the default value. Require the secret to be explicitly set. Validate minimum secret length (≥32 bytes). Fail startup if not configured.

---

### 🟠 VULN-005 — HIGH: SSRF (Server-Side Request Forgery) via `/echo` Endpoint

**File:** [`pkg/api/http/echo.go:40-98`](pkg/api/http/echo.go:40)  
**Type:** Server-Side Request Forgery (SSRF)

```go
if len(s.config.BackendURL) > 0 {
    for i, b := range s.config.BackendURL {
        go func(index int, backend string) {
            backendReq, err := http.NewRequestWithContext(ctx, "POST", backend, bytes.NewReader(body))
            // ...
            resp, err := client.Do(backendReq)  // ← makes HTTP request to configured backend
```

**Impact:** While the `BackendURL` is configured server-side (not user-controlled), the `/echo` endpoint forwards the **full request body** to backend services. If an attacker can influence the `BackendURL` configuration (via environment variable `PODINFO_BACKEND_URL`), they can redirect requests to internal services. Additionally, the body is forwarded verbatim, enabling request smuggling to internal services.

**Note:** The `BackendURL` is configurable via `--backend-url` flag or `PODINFO_BACKEND_URL` env var. If this is set to an internal service URL, the echo endpoint becomes a proxy to internal infrastructure.

**Remediation:** Validate and whitelist backend URLs. Implement URL allowlisting. Do not forward arbitrary request bodies to backend services without sanitization.

---

### 🟠 VULN-006 — HIGH: Unauthenticated Readiness State Manipulation

**File:** [`pkg/api/http/health.go:48-63`](pkg/api/http/health.go:48)  
**Type:** Unauthorized Access / Service Disruption

```go
func (s *Server) enableReadyHandler(w http.ResponseWriter, r *http.Request) {
    atomic.StoreInt32(&ready, 1)  // ← no auth check
    w.WriteHeader(http.StatusAccepted)
}

func (s *Server) disableReadyHandler(w http.ResponseWriter, r *http.Request) {
    atomic.StoreInt32(&ready, 0)  // ← no auth check
    w.WriteHeader(http.StatusAccepted)
}
```

**Impact:** Any unauthenticated POST to `/readyz/disable` removes the pod from the Kubernetes load balancer, effectively taking the service offline. Any POST to `/readyz/enable` can re-enable a pod that was intentionally disabled. This is a targeted DoS vector.

**Remediation:** Protect these endpoints with authentication or restrict to internal network only.

---

### 🟠 VULN-007 — HIGH: Unauthenticated `/token` Generation (Token Forgery)

**File:** [`pkg/api/http/token.go:27`](pkg/api/http/token.go:27)  
**Type:** Authentication Bypass / Privilege Escalation

```go
func (s *Server) tokenGenerateHandler(w http.ResponseWriter, r *http.Request) {
    user := "anonymous"
    if len(body) > 0 {
        user = string(body)  // ← user-controlled claim name
    }
    // ...
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    t, err := token.SignedString([]byte(s.config.JWTSecret))
```

**Impact:** Any unauthenticated user can POST to `/token` with any username in the body and receive a valid signed JWT token. Combined with VULN-004 (hardcoded secret), an attacker can generate tokens for any identity (e.g., `admin`, `root`, `system`). The token is valid for 1 minute, but can be continuously regenerated.

**Same issue in gRPC:** [`pkg/api/grpc/token.go:28`](pkg/api/grpc/token.go:28) — `TokenGenerate` requires no authentication.

**Remediation:** Require authentication before issuing tokens. Validate the requested identity against an authorization source.

---

### 🟠 VULN-008 — HIGH: Unauthenticated `/configs` Exposes Configuration Files

**File:** [`pkg/api/http/configs.go:5`](pkg/api/http/configs.go:5)  
**Type:** Sensitive Data Exposure / Information Disclosure

```go
func (s *Server) configReadHandler(w http.ResponseWriter, r *http.Request) {
    files := make(map[string]string)
    if watcher != nil {
        watcher.Cache.Range(func(key interface{}, value interface{}) bool {
            files[key.(string)] = value.(string)  // ← returns ALL config file contents
            return true
        })
    }
    s.JSONResponse(w, r, files)
}
```

**Impact:** Returns the full contents of all files in the configured `config-path` directory. In Kubernetes, this is typically a ConfigMap or Secret volume mount. This can expose:
- Database connection strings
- API keys
- TLS certificates
- Application secrets

**Remediation:** Protect with authentication. Consider filtering sensitive keys before returning.

---

### 🟠 VULN-009 — HIGH: Path Traversal / LFI in `/store/{hash}` Read

**File:** [`pkg/api/http/store.go:52-65`](pkg/api/http/store.go:52)  
**Type:** Local File Inclusion (LFI) / Path Traversal

```go
func (s *Server) storeReadHandler(w http.ResponseWriter, r *http.Request) {
    hash := mux.Vars(r)["hash"]
    content, err := os.ReadFile(path.Join(s.config.DataPath, hash))
    // ...
    w.Write([]byte(content))
}
```

**Impact:** The `hash` parameter from the URL is used directly in `path.Join()` without validation. While `path.Join` normalizes paths, an attacker can supply values like:
- `../etc/passwd` → reads `/etc/passwd` (path.Join resolves `..`)
- `../proc/self/environ` → reads process environment (same as `/env` but via filesystem)
- `../data/cert/tls.key` → reads TLS private key

**Note:** `path.Join` in Go does clean `..` traversal, but the route regex `{hash}` only restricts to the mux pattern — it does NOT restrict to alphanumeric. The gorilla/mux `{hash}` variable captures any non-slash characters by default, but `path.Join` will resolve `..` sequences.

**Verification:** `path.Join("/data", "../etc/passwd")` → `/etc/passwd` ✓ (confirmed traversal)

**Remediation:** Validate that `hash` matches a strict SHA1 hex pattern (`[0-9a-f]{40}`). Use `filepath.Clean` and verify the result is within `DataPath`.

---

### 🟠 VULN-010 — HIGH: Unauthenticated File Write to Disk via `/store`

**File:** [`pkg/api/http/store.go:23-41`](pkg/api/http/store.go:23)  
**Type:** Unauthorized File Write / Disk Exhaustion DoS

```go
func (s *Server) storeWriteHandler(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)  // ← no size limit
    // ...
    hash := hash(string(body))
    err = os.WriteFile(path.Join(s.config.DataPath, hash), body, 0644)
```

**Impact:**
1. **No request body size limit** — attacker can send gigabytes of data, exhausting disk space
2. **No authentication** — any user can write arbitrary files to the data directory
3. **No rate limiting** — unlimited writes possible
4. **File permissions 0644** — files are world-readable

**Remediation:** Add authentication, implement request body size limits (`http.MaxBytesReader`), add rate limiting, and restrict file permissions.

---

### 🟡 VULN-011 — MEDIUM: Denial of Service via `/delay/{wait}` — No Upper Bound

**File:** [`pkg/api/http/delay.go:55-69`](pkg/api/http/delay.go:55)  
**Type:** Denial of Service (Resource Exhaustion)

```go
func (s *Server) delayHandler(w http.ResponseWriter, r *http.Request) {
    delay, err := strconv.Atoi(vars["wait"])
    // ...
    time.Sleep(time.Duration(delay) * time.Second)
```

**Impact:** The route regex `{wait:[0-9]+}` only validates that the value is numeric, but does not enforce an upper bound. An attacker can request `/delay/999999999` to hold a goroutine for ~31 years, exhausting the server's goroutine pool and connection limits.

**Same issue in gRPC:** [`pkg/api/grpc/delay.go:17`](pkg/api/grpc/delay.go:17) — `DelayService.Delay()` sleeps for `delayInput.Seconds` with no upper bound.

**Remediation:** Enforce a maximum delay (e.g., 10 seconds). Return an error for values exceeding the limit.

---

### 🟡 VULN-012 — MEDIUM: Denial of Service via `/chunked/{wait}` — No Upper Bound

**File:** [`pkg/api/http/chunked.go:21-47`](pkg/api/http/chunked.go:21)  
**Type:** Denial of Service (Connection Exhaustion)

```go
func (s *Server) chunkedHandler(w http.ResponseWriter, r *http.Request) {
    delay, err := strconv.Atoi(vars["wait"])
    if err != nil {
        delay = rand.Intn(int(s.config.HttpServerTimeout*time.Second)-10) + 10
    }
    // ...
    time.Sleep(time.Duration(delay) * time.Second)
```

**Impact:** Similar to VULN-011. Additionally, the chunked response keeps the HTTP connection open for the duration, exhausting connection slots.

**Remediation:** Enforce maximum delay. Add authentication or rate limiting.

---

### 🟡 VULN-013 — MEDIUM: WebSocket Endpoint Has No Origin Check (CSWSH)

**File:** [`pkg/api/http/echows.go:13`](pkg/api/http/echows.go:13)  
**Type:** Cross-Site WebSocket Hijacking (CSWSH)

```go
var wsCon = websocket.Upgrader{}  // ← default upgrader, no CheckOrigin
```

**Impact:** The gorilla/websocket `Upgrader` with default settings accepts WebSocket connections from **any origin**. This enables Cross-Site WebSocket Hijacking (CSWSH) attacks where a malicious website can establish a WebSocket connection to the server on behalf of a victim user, potentially leaking data or performing actions.

**Remediation:** Set a `CheckOrigin` function that validates the `Origin` header against an allowlist:
```go
var wsCon = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return r.Header.Get("Origin") == "https://trusted-origin.com"
    },
}
```

---

### 🟡 VULN-014 — MEDIUM: Prometheus Metrics Exposed Without Authentication

**File:** [`pkg/api/http/server.go:97`](pkg/api/http/server.go:97)  
**Type:** Information Disclosure

```go
s.router.Handle("/metrics", promhttp.Handler())
```

**Impact:** Prometheus metrics are exposed on the main HTTP port without authentication. Metrics can reveal:
- Request rates and patterns (traffic analysis)
- Error rates (vulnerability scanning feedback)
- Internal service topology
- Performance characteristics useful for timing attacks

**Remediation:** Move metrics to a separate internal port (already supported via `--port-metrics` flag but not enforced). If on main port, protect with authentication.

---

### 🟡 VULN-015 — MEDIUM: gRPC Server Has No Authentication Interceptors

**File:** [`pkg/api/grpc/server.go:74`](pkg/api/grpc/server.go:74)  
**Type:** Missing Authentication

```go
srv := grpc.NewServer()  // ← no interceptors, no TLS, no auth
```

**Impact:** The gRPC server is created with no:
- TLS/mTLS configuration
- Authentication interceptors
- Authorization interceptors
- Rate limiting

All gRPC services (Echo, Version, Panic, Delay, Headers, Info, Status, TokenGenerate, Env) are accessible without any authentication.

**Remediation:** Add `grpc.UnaryInterceptor` and `grpc.StreamInterceptor` for authentication. Enable TLS with `grpc.Creds()`.

---

### 🟡 VULN-016 — MEDIUM: gRPC Reflection Enabled in Production

**File:** [`pkg/api/grpc/server.go:88`](pkg/api/grpc/server.go:88)  
**Type:** Information Disclosure

```go
reflection.Register(srv)
```

**Impact:** gRPC reflection allows any client to enumerate all available services, methods, and message types. This is equivalent to exposing an API schema to attackers, enabling automated exploitation of all gRPC endpoints.

**Remediation:** Disable reflection in production builds. Use build tags or configuration flags to enable only in development.

---

### 🔵 VULN-017 — LOW: TLS Certificate Check Disabled in CLI Tool

**File:** [`cmd/podcli/check.go:209`](cmd/podcli/check.go:209)  
**Type:** Insecure TLS Configuration

```go
conn := tls.Client(ipConn, &tls.Config{
    InsecureSkipVerify: true,  // ← disables certificate validation
    ServerName:         u.Hostname(),
})
```

**Impact:** The `InsecureSkipVerify: true` setting disables TLS certificate validation in the `check cert` CLI command. This makes the tool vulnerable to Man-in-the-Middle (MitM) attacks when checking certificate validity — ironically, the tool designed to check certificates doesn't validate them itself.

**Remediation:** Remove `InsecureSkipVerify: true`. Use the system certificate pool for validation.

---

### 🔵 VULN-018 — LOW: gRPC Client Uses Insecure Connection

**File:** [`cmd/podcli/check.go:279`](cmd/podcli/check.go:279)  
**Type:** Insecure Transport

```go
conn, err := grpc.Dial(address, grpc.WithInsecure())
```

**Impact:** The gRPC health check CLI uses `grpc.WithInsecure()`, transmitting data in plaintext. Credentials or sensitive data in gRPC metadata would be exposed to network eavesdropping.

**Remediation:** Use `grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))` for production connections.

---

### 🔵 VULN-019 — LOW: Error Messages Leak Internal File Paths

**File:** [`pkg/api/http/index.go:22-36`](pkg/api/http/index.go:22)  
**Type:** Information Disclosure

```go
if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    w.Write([]byte(path.Join(s.config.UIPath, "vue.html") + err.Error()))  // ← leaks path
    return
}
// ...
if err := tmpl.Execute(w, data); err != nil {
    http.Error(w, path.Join(s.config.UIPath, "vue.html")+err.Error(), ...)  // ← leaks path
}
```

**Impact:** Internal file system paths and template error details are returned directly to the client, revealing the server's directory structure.

**Remediation:** Log errors server-side and return generic error messages to clients.

---

### 🔵 VULN-020 — LOW: Deprecated `rand.Seed()` and Weak Randomness

**File:** [`pkg/api/http/http.go:18`](pkg/api/http/http.go:18), [`pkg/api/http/delay.go:30`](pkg/api/http/delay.go:30)  
**Type:** Weak Randomness

```go
rand.Seed(time.Now().Unix())  // ← deprecated, seeded with predictable value
if rand.Int31n(3) == 0 {
```

**Impact:** `rand.Seed` with `time.Now().Unix()` is predictable (second-level granularity). An attacker can predict when random errors will be triggered. While not directly exploitable for security bypass, it undermines the randomness guarantees.

**Remediation:** Use `crypto/rand` for security-sensitive operations. For non-security randomness, Go 1.20+ auto-seeds the global rand.

---

### ℹ️ VULN-021 — INFO: JWT Uses Deprecated `StandardClaims`

**File:** [`pkg/api/http/token.go:14`](pkg/api/http/token.go:14), [`pkg/api/grpc/token.go:23`](pkg/api/grpc/token.go:23)  
**Type:** Deprecated API Usage

```go
type jwtCustomClaims struct {
    Name string `json:"name"`
    jwt.StandardClaims  // ← deprecated in jwt/v4, use RegisteredClaims
}
```

**Impact:** `jwt.StandardClaims` is deprecated in `golang-jwt/jwt/v4`. The replacement `RegisteredClaims` uses `time.Time` instead of `int64` for time fields, reducing the risk of time comparison bugs.

**Remediation:** Migrate to `jwt.RegisteredClaims`.

---

### ℹ️ VULN-022 — INFO: No Rate Limiting on Any Endpoint

**Type:** Missing Security Control

**Impact:** No rate limiting is implemented on any endpoint. This enables:
- Brute force attacks on `/token/validate`
- Disk exhaustion via `/store` (see VULN-010)
- Connection exhaustion via `/delay` and `/chunked`
- Token generation flooding via `/token`

**Remediation:** Implement rate limiting middleware (e.g., `golang.org/x/time/rate` or a Redis-backed rate limiter).

---

### ℹ️ VULN-023 — INFO: No CORS Policy Defined

**Type:** Missing Security Header

**Impact:** No CORS headers are set. Depending on deployment context, this may allow cross-origin requests from any domain.

**Remediation:** Implement explicit CORS policy middleware.

---

### ℹ️ VULN-024 — INFO: No Content Security Policy (CSP) Headers

**Type:** Missing Security Header

**Impact:** The index page (`/`) renders HTML without CSP headers, potentially enabling XSS if template data is ever user-controlled.

**Remediation:** Add security headers middleware (CSP, X-Frame-Options, HSTS, etc.).

---

## 3. SUMMARY TABLE

| ID | Severity | Type | Endpoint/File |
|---|---|---|---|
| VULN-001 | 🔴 CRITICAL | DoS / Process Kill | `/panic`, gRPC `Panic` |
| VULN-002 | 🔴 CRITICAL | Sensitive Data Exposure | `/env`, gRPC `Env` |
| VULN-003 | 🔴 CRITICAL | Memory Dump / Info Disclosure | `/debug/pprof/` |
| VULN-004 | 🔴 CRITICAL | Hardcoded Secret | `main.go` JWT default |
| VULN-005 | 🟠 HIGH | SSRF | `/echo`, `/api/echo` |
| VULN-006 | 🟠 HIGH | Unauthorized State Manipulation | `/readyz/enable`, `/readyz/disable` |
| VULN-007 | 🟠 HIGH | Token Forgery | `/token`, gRPC `TokenGenerate` |
| VULN-008 | 🟠 HIGH | Config File Exposure | `/configs` |
| VULN-009 | 🟠 HIGH | LFI / Path Traversal | `/store/{hash}` |
| VULN-010 | 🟠 HIGH | Unauth File Write / DoS | `/store` |
| VULN-011 | 🟡 MEDIUM | DoS (goroutine exhaustion) | `/delay/{wait}`, gRPC `Delay` |
| VULN-012 | 🟡 MEDIUM | DoS (connection exhaustion) | `/chunked/{wait}` |
| VULN-013 | 🟡 MEDIUM | CSWSH | `/ws/echo` |
| VULN-014 | 🟡 MEDIUM | Info Disclosure | `/metrics` |
| VULN-015 | 🟡 MEDIUM | Missing Auth | gRPC server |
| VULN-016 | 🟡 MEDIUM | Info Disclosure | gRPC reflection |
| VULN-017 | 🔵 LOW | Insecure TLS | `podcli check cert` |
| VULN-018 | 🔵 LOW | Insecure Transport | `podcli check grpc` |
| VULN-019 | 🔵 LOW | Path Disclosure | `indexHandler` errors |
| VULN-020 | 🔵 LOW | Weak Randomness | `randomErrorMiddleware` |
| VULN-021 | ℹ️ INFO | Deprecated API | JWT `StandardClaims` |
| VULN-022 | ℹ️ INFO | Missing Control | No rate limiting |
| VULN-023 | ℹ️ INFO | Missing Header | No CORS policy |
| VULN-024 | ℹ️ INFO | Missing Header | No CSP headers |

---

## 4. ATTACK SCENARIOS

### Scenario A: Full Environment Variable Exfiltration
```
GET /env HTTP/1.1
Host: target:9898
```
→ Returns all environment variables including secrets, passwords, API keys.

### Scenario B: Persistent DoS via Panic
```
GET /panic HTTP/1.1
Host: target:9898
```
→ Kills the process. Repeat every time Kubernetes restarts the pod.

### Scenario C: Heap Memory Dump via pprof
```
GET /debug/pprof/heap HTTP/1.1
Host: target:9898
```
→ Downloads full heap dump. Parse with `go tool pprof` to extract JWT secrets, Redis passwords, etc.

### Scenario D: JWT Token Forgery (with default secret)
```
POST /token HTTP/1.1
Host: target:9898
Content-Type: text/plain

admin
```
→ Returns a signed JWT token with `name: "admin"`. Since the default secret is known, tokens can also be forged offline.

### Scenario E: Path Traversal to Read TLS Private Key
```
GET /store/../cert/tls.key HTTP/1.1
Host: target:9898
```
→ Attempts to read `/data/../cert/tls.key` = `/cert/tls.key`.

### Scenario F: Disk Exhaustion
```python
import requests
while True:
    requests.post("http://target:9898/store", data="A" * 100_000_000)
```
→ Fills disk with 100MB files until disk is full, crashing the service.

### Scenario G: Service Removal from Load Balancer
```
POST /readyz/disable HTTP/1.1
Host: target:9898
```
→ Removes pod from Kubernetes load balancer. Service becomes unreachable.

---

## 5. RECOMMENDED FIXES (Priority Order)

1. **Immediate:** Remove or gate `/panic` and gRPC `Panic` behind strong auth
2. **Immediate:** Remove or gate `/env` and gRPC `Env` behind strong auth  
3. **Immediate:** Move `/debug/pprof/` to internal-only port or remove
4. **Immediate:** Remove hardcoded JWT default secret; require explicit configuration
5. **High:** Add global authentication middleware for sensitive endpoints
6. **High:** Fix path traversal in `/store/{hash}` — validate hash format strictly
7. **High:** Add request body size limits to `/store` write handler
8. **High:** Protect `/readyz/enable` and `/readyz/disable` with auth
9. **High:** Add gRPC server interceptors for authentication
10. **Medium:** Disable gRPC reflection in production
11. **Medium:** Add WebSocket origin check
12. **Medium:** Enforce maximum delay values
13. **Medium:** Move metrics to internal port
14. **Low:** Fix `InsecureSkipVerify` in CLI tools
15. **Low:** Add rate limiting middleware
16. **Low:** Add security headers (CSP, CORS, HSTS)

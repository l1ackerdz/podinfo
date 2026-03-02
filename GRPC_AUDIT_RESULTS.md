# gRPC Security Audit — podinfo
**Target:** `test01.datagravity.pre.awscl.inditex.com`  
**Date:** 2026-03-02  
**Method:** Static code analysis + dynamic probing  

---

## gRPC Accessibility Status

**gRPC is NOT publicly accessible** on the live host.

| Port | Status | Notes |
|------|--------|-------|
| 443 (TLS) | HTTP 464 | Envoy blocks gRPC (`application/grpc` content-type rejected) |
| 9898 | CLOSED | HTTP port not publicly exposed |
| 9999 | CLOSED | Not listening |
| 50051 | CLOSED | Not listening |

**Root cause:** The gRPC server only starts if `--grpc-port > 0` (default is 0). The gRPC port is not configured in this deployment, or it is only accessible internally within the ECS cluster.

**Curl evidence:**
```bash
# All gRPC calls return HTTP 464 (Envoy custom error)
curl -sk --http2 -H "Content-Type: application/grpc" -H "TE: trailers" \
    -X POST "https://test01.datagravity.pre.awscl.inditex.com/env.EnvService/Env" \
    --data-binary $'\x00\x00\x00\x00\x00'
→ HTTP 464 (no content-type header — Envoy rejects gRPC)
```

---

## gRPC Static Code Analysis — Vulnerabilities

Even though gRPC is not currently publicly exposed, the following vulnerabilities exist in the gRPC server code and would be exploitable if the gRPC port were exposed:

---

### 🔴 GRPC-001 — CRITICAL: `EnvService.Env` Returns All Environment Variables

**File:** [`pkg/api/grpc/env.go`](pkg/api/grpc/env.go)  
**Proto:** `env.EnvService/Env`  

**Source code:**
```go
func (s *EnvServer) Env(ctx context.Context, envInput *pb.EnvRequest) (*pb.EnvResponse, error) {
    return &pb.EnvResponse{EnvVars: os.Environ()}, nil  // ← dumps ALL env vars
}
```

**Proto definition:**
```protobuf
service EnvService {
    rpc Env (EnvRequest) returns (EnvResponse) {}
}
message EnvRequest {}  // ← no parameters, no auth
message EnvResponse {
    repeated string envVars = 1;
}
```

**Impact:** Identical to HTTP `/env` — returns all environment variables including AWS credentials URI, Kafka broker URLs, secrets. No authentication required.

**grpcurl exploit (if port were exposed):**
```bash
grpcurl -plaintext -d '{}' HOST:9999 env.EnvService/Env
# Returns: {"envVars": ["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=...", "B=secret-b", ...]}
```

---

### 🔴 GRPC-002 — CRITICAL: `PanicService.Panic` Kills the Process

**File:** [`pkg/api/grpc/panic.go`](pkg/api/grpc/panic.go)  
**Proto:** `panic.PanicService/Panic`  

**Source code:**
```go
func (s *PanicServer) Panic(ctx context.Context, req *pb.PanicRequest) (*pb.PanicResponse, error) {
    s.logger.Info("Panic command received")
    os.Exit(225)  // ← kills the process immediately
    return &pb.PanicResponse{}, nil
}
```

**Proto definition:**
```protobuf
service PanicService {
    rpc Panic (PanicRequest) returns (PanicResponse) {}
}
message PanicRequest {}  // ← no parameters, no auth
```

**Impact:** Any unauthenticated gRPC call to `PanicService.Panic` immediately terminates the server process with exit code 225. In Kubernetes/ECS, this triggers a container restart. An attacker can continuously crash the service.

**grpcurl exploit (if port were exposed):**
```bash
grpcurl -plaintext -d '{}' HOST:9999 panic.PanicService/Panic
# Process exits immediately — pod restarts
```

---

### 🔴 GRPC-003 — CRITICAL: `TokenService.TokenGenerate` Issues JWT Without Authentication

**File:** [`pkg/api/grpc/token.go`](pkg/api/grpc/token.go)  
**Proto:** `token.TokenService/TokenGenerate`  

**Source code:**
```go
func (s *TokenServer) TokenGenerate(ctx context.Context, req *pb.TokenRequest) (*pb.TokenResponse, error) {
    user := "anonymous"  // ← hardcoded, no user input
    // ...
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    t, err := token.SignedString([]byte(s.config.JWTSecret))
    // ...
}
```

**Proto definition:**
```protobuf
service TokenService {
    rpc TokenGenerate (TokenRequest) returns (TokenResponse) {}
    rpc TokenValidate (TokenRequest) returns (TokenResponse) {}
}
message TokenRequest {}  // ← no parameters, no auth
```

**Note:** Unlike the HTTP endpoint, the gRPC `TokenGenerate` always uses `"anonymous"` as the username (the `TokenRequest` message has no fields). However, the token is still issued without authentication.

**grpcurl exploit (if port were exposed):**
```bash
grpcurl -plaintext -d '{}' HOST:9999 token.TokenService/TokenGenerate
# Returns: {"token": "eyJhbGci...", "expiresAt": "...", "message": "Token generated successfully"}
```

---

### 🔴 GRPC-004 — CRITICAL: gRPC Server Has No Authentication Interceptors

**File:** [`pkg/api/grpc/server.go:74`](pkg/api/grpc/server.go)  

**Source code:**
```go
srv := grpc.NewServer()  // ← no interceptors, no TLS, no auth
```

**Impact:** The gRPC server is created with:
- **No TLS** — all traffic in plaintext
- **No authentication interceptors** — no token validation on any method
- **No authorization interceptors** — no role-based access control
- **No rate limiting** — unlimited calls possible
- **No request size limits** — large messages accepted

All 9 gRPC services are accessible without any authentication.

---

### 🔴 GRPC-005 — CRITICAL: gRPC Reflection Enabled

**File:** [`pkg/api/grpc/server.go:88`](pkg/api/grpc/server.go)  

**Source code:**
```go
reflection.Register(srv)  // ← enables service enumeration
```

**Impact:** gRPC reflection allows any client to enumerate all available services, methods, and message types without knowing the proto files in advance.

**grpcurl exploit (if port were exposed):**
```bash
grpcurl -plaintext HOST:9999 list
# Returns:
# echo.EchoService
# env.EnvService
# grpc.health.v1.Health
# header.HeaderService
# info.InfoService
# panic.PanicService
# delay.DelayService
# status.StatusService
# token.TokenService
# version.VersionService
```

---

### 🟠 GRPC-006 — HIGH: `DelayService.Delay` — No Upper Bound (DoS)

**File:** [`pkg/api/grpc/delay.go`](pkg/api/grpc/delay.go)  

**Source code:**
```go
func (s *DelayServer) Delay(ctx context.Context, delayInput *pb.DelayRequest) (*pb.DelayResponse, error) {
    time.Sleep(time.Duration(delayInput.Seconds) * time.Second)  // ← no upper bound
    return &pb.DelayResponse{Message: delayInput.Seconds}, nil
}
```

**Proto:**
```protobuf
message DelayRequest {
    int64 seconds = 1;  // ← int64, accepts 9223372036854775807
}
```

**Impact:** An attacker can send `{"seconds": 9223372036854775807}` (max int64) to hold a goroutine for ~292 billion years. No upper bound validation.

**grpcurl exploit (if port were exposed):**
```bash
grpcurl -plaintext -d '{"seconds": 9223372036854775807}' HOST:9999 delay.DelayService/Delay
# Goroutine held indefinitely
```

---

### 🟠 GRPC-007 — HIGH: `InfoService.Info` — Runtime Information Disclosure

**File:** [`pkg/api/grpc/info.go`](pkg/api/grpc/info.go)  

**Proto:**
```protobuf
message InfoResponse {
    string hostname = 1;
    string version = 2;
    string revision = 3;
    string color = 4;
    string logo = 5;
    string message = 6;
    string goos = 7;
    string goarch = 8;
    string runtime = 9;
    string numgoroutine = 10;
    string numcpu = 11;
}
```

**Impact:** Returns full runtime information including internal hostname, Go version, CPU architecture, goroutine count — same as HTTP `/api/info`.

---

### 🟠 GRPC-008 — HIGH: `TokenService.TokenValidate` — Error Message Leaks Token Details

**File:** [`pkg/api/grpc/token.go:68`](pkg/api/grpc/token.go)  

**Source code:**
```go
if strings.Contains(err.Error(), "token is expired") || strings.Contains(err.Error(), "signature is invalid") {
    return &pb.TokenResponse{
        Message: err.Error(),  // ← leaks internal JWT error details
    }, nil
}
```

**Impact:** JWT validation errors are returned verbatim to the client, leaking internal error messages that could help an attacker understand the token validation logic.

---

### 🟡 GRPC-009 — MEDIUM: `EchoService.Echo` — Message Body Logged

**File:** [`pkg/api/grpc/echo.go`](pkg/api/grpc/echo.go)  

**Source code:**
```go
func (s *echoServer) Echo(ctx context.Context, message *echo.Message) (*echo.Message, error) {
    s.logger.Info("Received message body from client:", zap.String("input body", message.Body))
    return &echo.Message{Body: message.Body}, nil
}
```

**Impact:** The full message body is logged at INFO level. If the body contains sensitive data (tokens, passwords, PII), it will appear in application logs.

---

### 🟡 GRPC-010 — MEDIUM: `StatusService.Status` — Arbitrary Status Code

**File:** [`pkg/api/grpc/status.go`](pkg/api/grpc/status.go)  
**Proto:**
```protobuf
message StatusRequest {
    string code = 1;  // ← string, no validation
}
```

**Impact:** The status code is a string with no validation — any value can be passed. The HTTP equivalent accepts invalid codes like 999.

---

## gRPC Services Summary

| Service | Method | Auth | Risk | Notes |
|---------|--------|------|------|-------|
| `EchoService` | `Echo` | ❌ None | 🟡 MEDIUM | Body logged |
| `VersionService` | `Version` | ❌ None | ℹ️ INFO | Version disclosure |
| `PanicService` | `Panic` | ❌ None | 🔴 CRITICAL | Kills process |
| `DelayService` | `Delay` | ❌ None | 🟠 HIGH | No upper bound (int64) |
| `HeaderService` | `Header` | ❌ None | 🔵 LOW | Header reflection |
| `InfoService` | `Info` | ❌ None | 🟠 HIGH | Runtime info disclosure |
| `StatusService` | `Status` | ❌ None | 🔵 LOW | Arbitrary status |
| `TokenService` | `TokenGenerate` | ❌ None | 🔴 CRITICAL | JWT issued without auth |
| `TokenService` | `TokenValidate` | ❌ None | 🟠 HIGH | Error message leakage |
| `EnvService` | `Env` | ❌ None | 🔴 CRITICAL | All env vars exposed |
| `grpc.health.v1.Health` | `Check` | ❌ None | ℹ️ INFO | Health check |

---

## Dynamic Testing Results

```
grpcurl -insecure HOST:443 env.EnvService/Env
→ ERROR: unexpected HTTP status code 464 — Envoy blocks gRPC

grpcurl -plaintext HOST:9898 env.EnvService/Env
→ ERROR: context deadline exceeded — port not publicly accessible

grpcurl -plaintext HOST:9999 env.EnvService/Env
→ ERROR: context deadline exceeded — port not publicly accessible
```

**Conclusion:** The gRPC server is **not publicly accessible** on this deployment. The Envoy ingress does not route gRPC traffic. However, if the gRPC port were exposed (e.g., via internal network access, misconfigured ingress, or direct pod access), all 10 services would be accessible without authentication.

---

## Remediation

1. **Add authentication interceptors** to the gRPC server:
```go
srv := grpc.NewServer(
    grpc.UnaryInterceptor(authInterceptor),
    grpc.StreamInterceptor(streamAuthInterceptor),
)
```

2. **Enable TLS** for gRPC:
```go
creds, _ := credentials.NewServerTLSFromFile(certFile, keyFile)
srv := grpc.NewServer(grpc.Creds(creds))
```

3. **Disable reflection in production**:
```go
// Only register reflection in development
if config.Debug {
    reflection.Register(srv)
}
```

4. **Add delay upper bound**:
```go
if delayInput.Seconds > 10 {
    return nil, status.Errorf(codes.InvalidArgument, "delay must be <= 10 seconds")
}
```

5. **Remove or protect `PanicService`** — never expose process-killing endpoints.

6. **Remove or protect `EnvService`** — never expose environment variables.

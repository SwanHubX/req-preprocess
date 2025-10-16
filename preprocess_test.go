package req_preprocess

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// Functions for testing

// GenerateRSAKeyPair 生成 RSA 密钥对
func GenerateRSAKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// 生成随机字符串
func randomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic("生成随机字符串失败")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Target: func splitToken(prefix string, authorization string) JWT
// cases:
// 1. 正确格式的 token，返回正确的 JWT 结构
// 2. 假随机字符，返回空 JWT 结构
// 3. 无效 token 格式，返回非法切割的 JWT 结构

func TestSplitToken_OK(t *testing.T) {
	prefix := "Bearer"
	validAuthorization := "Bearer header.payload.signature"

	// 测试格式有效的情况
	jwt := splitToken(prefix, validAuthorization)
	if jwt.header != "header" || jwt.payload != "payload" || jwt.signature != "signature" {
		t.Errorf("splitToken 未正确分割有效令牌")
	}
}

func TestSplitToken_FakeToken(t *testing.T) {
	randomLength, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		t.Fatalf("TestSplitToken_FakeToken 生成随机数失败: %v", err)
	}

	prefix := "Bearer"
	fakeAuthorization := "Bearer " + randomString(int(randomLength.Int64()))

	// 测试假随机字符的情况
	jwt := splitToken(prefix, fakeAuthorization)
	if jwt.header != "" || jwt.payload != "" || jwt.signature != "" {
		t.Errorf("splitToken 处理假随机字符时应返回空")
	}
}

func TestSplitToken_InvalidPrefix(t *testing.T) {
	prefix := "Bearer"
	invalidAuthorization := "ImNotBearer InvalidToken.DoNot.SplitMe"

	// 测试无效 token 格式的情况
	jwt := splitToken(prefix, invalidAuthorization)
	if jwt.header != "ImNotBearer InvalidToken" || jwt.payload != "DoNot" || jwt.signature != "SplitMe" {
		t.Errorf("对于无效令牌，splitToken 应返回非法切割的JWT")
	}
}

// Target: func loadPublicKey(key string) *rsa.PublicKey
// cases:
// 1. 正确的 PEM 格式公钥，返回正确的 *rsa.PublicKey

func TestLoadPublicKey(t *testing.T) {
	// 生成测试用的 RSA 密钥对
	_, publicKey := GenerateRSAKeyPair(t)

	// 将公钥编码为 PEM 格式
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("公钥编码失败: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	loadedPublicKey := loadPublicKey(string(pubPEM))
	if loadedPublicKey == nil {
		t.Fatal("loadPublicKey 返回了 nil")
	}

	// 比较加载后的公钥与原始公钥
	if loadedPublicKey.N.Cmp(publicKey.N) != 0 || loadedPublicKey.E != publicKey.E {
		t.Error("加载后的公钥与原始公钥不匹配")
	}
}

// Target: func verifyJWT(jwt JWT, key *rsa.PublicKey) bool
// cases:
// 1. 有效签名的 JWT，函数返回 true
// 2. 无效签名的 JWT，函数返回 false

func TestVerifyJWT_OK(t *testing.T) {
	// 生成测试用的 RSA 密钥对
	privateKey, publicKey := GenerateRSAKeyPair(t)

	// 构建 JWT 组件
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"Hello SwanHub","iat":1145141919810}`))
	message := header + "." + payload

	// 签名处理
	hashed := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	// 构建 JWT 结构
	jwt := JWT{
		header:    header,
		payload:   payload,
		signature: signatureEncoded,
	}

	// 验证 JWT 签名
	if !verifyJWT(jwt, publicKey) {
		t.Error("verifyJWT 未能验证有效的 JWT")
	}
}

func TestVerifyJWT_InvalidSignature(t *testing.T) {
	// 生成测试用的 RSA 密钥对
	_, publicKey := GenerateRSAKeyPair(t)

	// 构建 JWT 组件
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"Hello SwanHub","iat":1145141919810}`))
	signatureEncoded := "invalidsignature"

	// 构建错误签名的 JWT 结构
	jwt := JWT{
		header:    header,
		payload:   payload,
		signature: signatureEncoded,
	}

	// 验证 JWT 签名
	if verifyJWT(jwt, publicKey) {
		t.Error("verifyJWT 应该拒绝无效的签名")
	}
}

// Target: func verifyExpires(exp int64) bool
// cases:
// 1. 已过期时间戳，函数返回 true
// 2. 未过期时间戳，函数返回 false

func TestVerifyExpires_Past(t *testing.T) {
	// 测试已过期时间戳
	expPast := time.Now().Add(-10 * time.Minute).Unix()
	if !verifyExpires(expPast) {
		t.Error("对于已过期时间戳，verifyExpires 应该返回 true")
	}
}

func TestVerifyExpires_Future(t *testing.T) {
	// 测试未过期时间戳
	expFuture := time.Now().Add(10 * time.Minute).Unix()
	if verifyExpires(expFuture) {
		t.Error("对于未过期时间戳，verifyExpires 应该返回 false")
	}
}

// Target: func uuid() string
// cases:
// 1. 符合生成逻辑的 UUID 字符串，验证字符串长度、时间戳部分和随机部分

func TestUuid(t *testing.T) {
	id := uuid()
	if len(id) < 16 {
		t.Errorf("uuid 应该返回至少 16 个字符的字符串，但返回 %d 个字符", len(id))
	}

	// 验证前 8 个字符是否为 Base36 编码的时间戳
	timestampPart := id[:8]
	_, err := strconv.ParseInt(timestampPart, 36, 64)
	if err != nil {
		t.Errorf("uuid 的前 8 个字符应为 Base36 编码的时间戳，解析失败: %v", err)
	}

	// 验证剩余部分是否为字母数字字符
	randomPart := id[8:]
	if len(randomPart) != 8 {
		t.Errorf("uuid 的随机部分应为 8 个字符，但返回 %d 个字符", len(randomPart))
	}
}

// Target: func (p *Preprocess) addTraceId(req *http.Request, rw http.ResponseWriter)
// cases:
// 1. 确认请求和响应的 TraceId 已设置、长度正确

func TestAddTraceId(t *testing.T) {
	// 创建 Preprocess 实例
	p := &Preprocess{}

	// 创建 HTTP 请求和响应记录器
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	rw := httptest.NewRecorder()

	// 调用 addTraceId
	p.addTraceId(req, rw)

	// 检查 TraceId 头在请求和响应中是否已设置
	reqTraceId := req.Header.Get("TraceId")
	respTraceId := rw.Header().Get("TraceId")

	if reqTraceId == "" || respTraceId == "" {
		t.Error("addTraceId 未能设置 TraceId 头")
	}

	if reqTraceId != respTraceId {
		t.Error("请求和响应中的 TraceId 不匹配")
	}

	if len(reqTraceId) < 16 {
		t.Errorf("TraceId 应该至少有 16 个字符，但实际是 %d 个字符", len(reqTraceId))
	}
}

// Target: func (p *Preprocess) ServeHTTP(rw http.ResponseWriter, req *http.Request)
// cases(simple，串联测试多个函数):
// 1. 通过 JWT 验证的请求，检查 Payload 头是否已设置
// 2. 通过 TraceId 生成的请求，检查 TraceId 头是否已设置

func TestServeHTTP_ByJWT(t *testing.T) {
	// 设置
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// 将公钥编码为 PEM 格式
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("公钥编码失败: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	// 创建测试用的 JWT 令牌
	headerJSON := `{"alg":"RS256","typ":"JWT"}`
	payloadMap := map[string]interface{}{
		"sub":  "1234567890",
		"name": "Hello SwanHub",
		"iat":  1145141919810,
		"exp":  time.Now().Add(10 * time.Minute).Unix(),
	}
	payloadJSON, _ := json.Marshal(payloadMap)

	header := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	message := header + "." + payload

	hashed := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)
	token := "Bearer " + message + "." + signatureEncoded

	// 创建 Preprocess 实例
	config := &Config{
		Key: string(pubPEM),
	}
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 在这里检查 Payload 头是否已设置
		payloadHeader := r.Header.Get("Payload")
		if payloadHeader == "" {
			t.Error("Payload 头应该被设置")
		}
		w.WriteHeader(http.StatusOK)
	})
	handler, err := New(context.Background(), nextHandler, config, "test")
	if err != nil {
		t.Fatalf("创建 Preprocess 处理器失败: %v", err)
	}

	// 创建带有 Authorization 头的 HTTP 请求
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	req.Header.Set("Authorization", token)
	rw := httptest.NewRecorder()

	// 处理请求
	handler.ServeHTTP(rw, req)

	// 检查响应状态码是否正确
	if status := rw.Code; status != http.StatusOK {
		t.Errorf("处理器错误: 返回 %v, 期望 %v", status, http.StatusOK)
	}
}

func TestServeHTTP_ByTraceId(t *testing.T) {
	// 创建 Preprocess 实例
	config := &Config{}
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查 TraceId 是否已设置
		traceId := r.Header.Get("TraceId")
		if traceId == "" {
			t.Error("TraceId 头应该在请求中设置")
		}
		w.WriteHeader(http.StatusOK)
	})
	handler, err := New(context.Background(), nextHandler, config, "test")
	if err != nil {
		t.Fatalf("创建 Preprocess 处理器失败: %v", err)
	}

	// 创建 HTTP 请求
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	rw := httptest.NewRecorder()

	// 处理请求
	handler.ServeHTTP(rw, req)

	// 检查响应中的 TraceId 是否设置
	traceId := rw.Header().Get("TraceId")
	if traceId == "" {
		t.Error("TraceId 头应该在响应中设置")
	}
}

func TestForwardAuth_CookieSid(t *testing.T) {
	// 创建一个测试服务器来模拟认证服务
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否正确接收到了 sid
		sid, err := r.Cookie("sid")
		if err != nil {
			t.Errorf("认证服务未收到 sid cookie: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if sid.Value != "test-session-id-123" {
			t.Errorf("期望 sid 为 'test-session-id-123', 但实际为 '%s'", sid.Value)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// 返回模拟的认证结果
		w.WriteHeader(http.StatusOK)
		// 随便返回一点 看看payload有没有正确设置
		w.Write([]byte(`{"userId":"12345","username":"testuser"}`))
	}))
	defer authServer.Close()

	// 创建 Preprocess 实例
	config := &Config{
		AuthUrl: authServer.URL,
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否正确设置了 Payload 头
		payload := r.Header.Get("Payload")
		if payload == "" {
			t.Error("Payload 头应该被设置")
		}
		if payload != `{"userId":"12345","username":"testuser"}` {
			t.Errorf("Payload 头内容错误: %s", payload)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), nextHandler, config, "test")
	if err != nil {
		t.Fatalf("创建 Preprocess 处理器失败: %v", err)
	}

	// 创建带有 sid cookie 的 HTTP 请求
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}

	// 添加 sid cookie
	req.AddCookie(&http.Cookie{
		Name:  "sid",
		Value: "test-session-id-123",
	})

	rw := httptest.NewRecorder()

	// 处理请求
	handler.ServeHTTP(rw, req)

	// 检查响应状态码
	if status := rw.Code; status != http.StatusOK {
		t.Errorf("处理器错误: 返回 %v, 期望 %v", status, http.StatusOK)
	}
}

func TestForwardAuth_HeaderXSid(t *testing.T) {
	// 创建一个测试服务器来模拟认证服务
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否正确使用 X-SID 而不是 cookie 中的 sid
		xSid := r.Header.Get("X-SID")
		if xSid != "header-session-id-456" {
			t.Errorf("期望 X-SID 为 'header-session-id-456', 但实际为 '%s'", xSid)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// 返回模拟的认证结果
		w.WriteHeader(http.StatusOK)
		// 随便返回一点 看看payload有没有正确设置
		w.Write([]byte(`{"userId":"67890","username":"headeruser"}`))
	}))
	defer authServer.Close()

	// 创建 Preprocess 实例
	config := &Config{
		AuthUrl: authServer.URL,
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否正确设置了 Payload 头
		payload := r.Header.Get("Payload")
		if payload == "" {
			t.Error("Payload 头应该被设置")
		}
		if payload != `{"userId":"67890","username":"headeruser"}` {
			t.Errorf("Payload 头内容错误: %s", payload)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), nextHandler, config, "test")
	if err != nil {
		t.Fatalf("创建 Preprocess 处理器失败: %v", err)
	}

	// 创建 HTTP 请求，同时设置 cookie 和请求头
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}

	// 添加 sid cookie 但不应该被使用
	req.AddCookie(&http.Cookie{
		Name:  "sid",
		Value: "cookie-session-id-123",
	})

	// 设置 X-SID 请求头 应当使用
	req.Header.Set("X-SID", "header-session-id-456")

	rw := httptest.NewRecorder()

	// 处理请求
	handler.ServeHTTP(rw, req)

	// 检查响应状态码
	if status := rw.Code; status != http.StatusOK {
		t.Errorf("处理器错误: 返回 %v, 期望 %v", status, http.StatusOK)
	}
}

func TestForwardAuth_NoSid(t *testing.T) {
	// 创建一个测试服务器来模拟认证服务
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 这个测试不应该调用认证服务
		// 就是没有 sid 就不应该转发
		t.Error("不应该调用认证服务，因为请求中没有 sid")
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer authServer.Close()

	// 创建 Preprocess 实例
	config := &Config{
		AuthUrl: authServer.URL,
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否没有设置 Payload 头
		payload := r.Header.Get("Payload")
		if payload != "" {
			t.Error("Payload 头不应该被设置，因为没有提供 sid")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), nextHandler, config, "test")
	if err != nil {
		t.Fatalf("创建 Preprocess 处理器失败: %v", err)
	}

	// 创建 HTTP 请求，不提供 sid
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}

	rw := httptest.NewRecorder()

	// 处理请求
	handler.ServeHTTP(rw, req)

	// 检查响应状态码
	if status := rw.Code; status != http.StatusOK {
		t.Errorf("处理器错误: 返回 %v, 期望 %v", status, http.StatusOK)
	}
}

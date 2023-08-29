package req_preprocess

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	AuthUrl string // 认证服务url
	Key     string // JWT公钥
}

func CreateConfig() *Config {
	return &Config{
		AuthUrl: "",
		Key:     "",
	}
}

type Preprocess struct {
	next      http.Handler
	name      string
	url       string
	publicKey *rsa.PublicKey
}

// Response 响应对象
type Response struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// JWT JWT对象格式
type JWT struct {
	header    string
	payload   string
	signature string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	publicKey := loadPublicKey(config.Key) // 加载pem公钥
	return &Preprocess{
		next:      next,
		name:      name,
		url:       config.AuthUrl,
		publicKey: publicKey,
	}, nil
}

func (p *Preprocess) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.forwardAuth(req) // 对会话进行转发验证
	p.parseJWT(req)    // 对携带JWT凭证的请求进行解析
	p.next.ServeHTTP(rw, req)
}

/*
将会话id转发给认证接口，用于检索会话信息传递给后面的真实接口
会话id保留在cookie中的sid字段中
*/
func (p *Preprocess) forwardAuth(req *http.Request) {
	sid, err := req.Cookie("sid")
	if err != nil {
		return
	}
	fReq, err := http.NewRequest("GET", p.url, nil)
	if err != nil {
		return
	}
	fReq.AddCookie(sid) // 携带会话id
	res, err := http.DefaultClient.Do(fReq)
	if err != nil {
		return
	}
	defer res.Body.Close()
	// 处理响应，转化为JSON
	var result Response
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil || result.Code != 0 {
		return
	}
	req.Header.Add("payload", string(result.Data))
}

// ----- JWT相关 -----

func (p *Preprocess) parseJWT(req *http.Request) {
	authorization := req.Header.Get("Authorization")
	if authorization != "" {
		// 1. 将token解析为JWT格式
		jwt := splitToken("Bearer", authorization)
		if jwt.header == "" {
			return
		}
		// 2. 验证jwt凭证是否有效
		if ok := verifyJWT(jwt, p.publicKey); !ok {
			return
		}
		payload, err := base64.RawURLEncoding.DecodeString(jwt.payload)
		if err != nil {
			return
		}
		// 3. 验证jwt凭证是否过期
		var v map[string]interface{}
		if err = json.Unmarshal(payload, &v); err != nil {
			return
		}
		exp := int64(math.Floor(v["exp"].(float64)))
		if verifyExpires(exp) {
			return
		}
		req.Header.Add("payload", string(payload))
	}
}

// 加载pem格式公钥
func loadPublicKey(key string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(key))
	parsedKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	rsaPublicKey := parsedKey.(*rsa.PublicKey)
	return rsaPublicKey
}

// 用于解析token为JWT数据格式
func splitToken(prefix string, authorization string) JWT {
	token := strings.TrimSpace(strings.TrimPrefix(authorization, prefix)) // remove prefix Bearer
	pToken := strings.Split(token, ".")
	if len(pToken) != 3 {
		return JWT{}
	}
	return JWT{
		header:    pToken[0],
		payload:   pToken[1],
		signature: pToken[2],
	}
}

// 验证token是否签名有效
// 有效返回true，无效则返回false
func verifyJWT(jwt JWT, key *rsa.PublicKey) bool {
	hashed := sha256.Sum256([]byte(jwt.header + "." + jwt.payload))
	sign, err := base64.RawURLEncoding.DecodeString(jwt.signature)
	if err != nil {
		return false
	}
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], sign) == nil
}

// 验证token是否过期。true代表已过期
func verifyExpires(exp int64) bool {
	return exp < time.Now().Unix()
}

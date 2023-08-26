package req_preprocess

import (
	"context"
	"encoding/json"
	"net/http"
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
	next http.Handler
	name string
	url  string
	key  string
}

// Response 响应对象
type Response struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Preprocess{
		next: next,
		name: name,
		url:  config.AuthUrl,
		key:  config.Key,
	}, nil
}

func (p *Preprocess) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	forwardAuth(p, req) // 对会话进行转发验证
	p.next.ServeHTTP(rw, req)
}

/*
将会话id转发给认证接口，用于检索会话信息传递给后面的真实接口
会话id保留在cookie中的sid字段中
*/
func forwardAuth(p *Preprocess, req *http.Request) {
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

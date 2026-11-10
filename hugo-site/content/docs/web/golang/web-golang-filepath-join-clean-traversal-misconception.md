---
id: web-golang-filepath-join-clean-traversal-misconception
title: Go filepath.Join/Clean 目录遍历误区：.. 在相对 base 下保留、绝对 base 下仍可逃出基目录
type: scenario
domain: web
path: web/golang
technique: go-filepath-join-clean-traversal-misconception
tags:
- go
- golang
- path-traversal
- filepath
- join
- clean
- security-audit
- file-read
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T08:04:09+08:00'
  notes: 已对照原文与5张图核对：图01 filepath.Join 官方文档（结果被 Clean）、图02 Join 输出 ytm.com/b 与 ../../.../b/c、图03 Go1.18.2 path.go Clean 的 dotdot switch 分支、图04 Clean(Join) 仍保留前导 ..。卡内语义、PoC 输出（Join/Clean 幂等、相对 base 保留 ..、绝对 base 逃逸）与原文一致；filepath.IsLocal 为 Go1.20+ 亦正确。原文未给组件版本，affected_versions 空正确。dedup 最高分为卡自身，其余 related 为 Python/Java 路径拼接，非同一链；dup-scan 无本篇 pair。未实际读文件验证 sink。
url: /docs/web/golang/web-golang-filepath-join-clean-traversal-misconception/
draft: false
kb_aliases:
- filepath.Join 目录遍历
- filepath.Clean 绕过
- Go 路径穿越
- .. 保留
- Go 安全审计路径
---

## 一句话结论

Go 的 `filepath.Join` 会调用 `filepath.Clean`，但 Clean 只做词法归一化，并不保证结果留在某个基目录内：相对 base 下 `a/../../../../b` 会保留前导 `../..`，绝对 base 下 `../../etc/passwd` 也会逃到 `/etc/passwd`；把 Join/Clean 当目录遍历防御是误解，正确做法是用 `filepath.Rel`/`filepath.IsLocal`/绝对路径前缀校验把结果限制在基目录内。

## 原理

- **Join 的语义**：`filepath.Join(elem...)` 用操作系统分隔符拼接所有非空元素，并对结果执行 `Clean`。它只负责“拼成一个规范路径”，不负责“限制在某个目录下”。
- **Clean 的语义**：替换重复分隔符、去掉 `.`、在可回溯时消掉 `..` 及其前一个元素；但当路径是相对的且 `..` 已经回溯到开头、无法再消时，Clean 会**保留前导 `..`**（Go `path/filepath/path.go` 中对 `..` 的 switch-case 分支）。因此 `filepath.Clean("../..")` 仍是 `../..`。
- **相对 base 下的逃逸**：`filepath.Join("uploads", "a/../../../../b/c")` 先拼成 `uploads/a/../../../../b/c`，Clean 后变成 `../../b/c`——前导 `..` 保留，直接指向 base 的上级目录。再套一层 `filepath.Clean(filepath.Join(...))` 也不会改变（Join 已经 Clean 过，Clean 幂等）。
- **绝对 base 下的逃逸**：`filepath.Join("/var/www", "../../etc/passwd")` 得到 `/etc/passwd`；虽然根目录的 `..` 会被丢弃，但结果已经离开 `/var/www`。可见“用了 Join/Clean”与“没有穿越”是两件事。
- **危害成立点**：Join 的结果若直接交给 `os.Open`/`os.ReadFile`/`http.ServeFile` 等 sink，且攻击者能控制其中一个路径元素，就能读取/写入基目录之外的文件；如果 base 是相对路径（如 `"uploads"`、`"data"`），前导 `..` 会让逃逸更直接。
- **正确边界校验**：把 base 与目标都转绝对路径，用 `filepath.Rel(baseAbs, targetAbs)` 得到相对路径，拒绝以 `..` 开头或为绝对路径的结果（Go 1.20+ 可直接用 `filepath.IsLocal(rel)`）；也可以使用按目录打开的文件系统 API 做真正的根目录约束。

## 触发条件

- 代码用 `filepath.Join(base, userInput)` 或 `filepath.Clean(filepath.Join(...))` 构造文件路径，base 为相对或绝对目录。
- `userInput` 可被攻击者控制且未做文件名白名单/路径边界校验；包含 `../` 或足够多的 `..`。
- Join 结果进入文件读取/写入/下载/包含等 sink，进程对目标文件有读/写权限。
- 开发者误以为 Join/Clean 已经阻止穿越（常见于代码审计）。

## 利用步骤

1. 在源码中搜索 `filepath.Join(`、`filepath.Clean(`，标记第二个及后续参数来自请求/数据库/配置的调用点。
2. 判断 base 是相对还是绝对：相对 base 用 `../` 即可逃逸；绝对 base 需向上走到根/其他目录（如 `/var/www` + `../../etc/passwd`）。
3. 构造输入（如 `../../etc/passwd`、`a/../../../../b/c`），观察 Join 结果是否仍以 `..` 开头或已指向基目录之外。
4. 把该输入送进实际 sink（下载接口、模板包含、日志读取等），验证能否读到基目录外文件。
5. 若存在文件名后缀/白名单，配合 `..%2f`、双重编码、`filepath.Clean` 前后的差异等变形继续测试（视框架而定）。

## PoC

```go
package main

import (
    "fmt"
    "path/filepath"
)

func main() {
    base := "uploads" // 相对 base；换成 "/var/www" 同样可逃逸到其他绝对目录
    inputs := []string{
        "../../etc/passwd",
        "a/../../../../b/c",
    }
    for _, in := range inputs {
        fmt.Println("Join       :", filepath.Join(base, in))
        fmt.Println("Clean(Join):", filepath.Clean(filepath.Join(base, in)))
    }
}
```

典型输出（与原文演示一致的前导 `..` 行为）：

```text
Join       : ../etc/passwd
Clean(Join): ../etc/passwd
Join       : ../../b/c
Clean(Join): ../../b/c
```

安全写法（边界校验）：

```go
baseAbs, _ := filepath.Abs(base)
targetAbs, _ := filepath.Abs(filepath.Join(base, userInput))
rel, err := filepath.Rel(baseAbs, targetAbs)
if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
    return errors.New("path escape")
}
// Go 1.20+ 也可用 filepath.IsLocal(rel) 判断
```

## 变体与关联

- **变体**：Python `os.path.join(base, "/abs")` 会丢弃 base；Java `Path.resolve` 遇绝对路径覆盖 base；PHP `open_basedir` 的字符串前缀校验可被 symlink/`glob://` 绕过；这些都属于“路径拼接 API 不保证边界”的同类问题。
- **关联卡片**：[[web-generic-file-inclusion-python-os-path-join-absolute-traversal]]（Python 绝对路径覆盖）；[[web-generic-file-inclusion-java-path-resolve-absolute-override]]（Java Path.resolve）；[[web-golang-servemux-encoded-slash-path-traversal]]（Go ServeMux 的 %2F 双视图）；[[web-generic-file-inclusion-go-newreplacer-dotdot-doublewrite-bypass]]（Go NewReplacer 双写绕过）。
- **区分**：本卡的核心是 Go `filepath.Join`/`Clean` 的语义不提供目录边界，不是某个框架/组件的具体 CVE。

## 检测与防御

- **代码审计**：所有 `filepath.Join(base, userInput)` 都视为潜在穿越点；检查是否有 `filepath.Rel`/`filepath.IsLocal`/绝对前缀比较等边界校验，而不是只看有没有 Clean。
- **修复**：用 `filepath.Abs` + `filepath.Rel` 做包含性检查；用文件名白名单（仅允许 `[a-zA-Z0-9._-]`）；用按目录打开的 API/`os.Root`（新版本 Go）或 `openat2(RESOLVE_BENEATH)` 做内核级约束。
- **运行**：Web 进程最小权限、敏感文件放在不可读目录；对下载/读取接口做路径规范化日志与异常告警。
- **测试**：对路径参数做 fuzz（`..`、混合分隔符、编码、绝对路径、超长 `..`），验证结果始终位于基目录内。

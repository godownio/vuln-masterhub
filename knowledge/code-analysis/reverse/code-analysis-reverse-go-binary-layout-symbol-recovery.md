---
id: code-analysis-reverse-go-binary-layout-symbol-recovery
title: Go 二进制逆向基础：string/slice/map 内存布局、调用约定与 stripped 符号恢复
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: go-binary-layout-symbol-recovery
aliases:
- Go 逆向
- Golang 二进制分析
- go_parser
- redress
- Go string header
- Go 符号恢复
- runtime.concatstring
tags:
- go
- golang
- reverse
- binary-analysis
- symbol-recovery
- data-structure
- ida
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:03:23+08:00'
  notes: 已对照 content.md 与 14 张图核对：concatstring3/concatstrings、makeslice、string/slice/array 布局、栈传参、Person 方法、go_parser/redress、.rdata string header 扫描脚本均一致。文章把 array 简化为 {Data,Len} 头（Go 实际数组无此 header），卡片照原文表述并限定“文章的描述中”；未在本机运行 IDA/go_parser/redress。frontmatter 无 sources/source_url。
---

## 一句话结论

Go 二进制即使被 `-ldflags="-w -s"` 去掉符号表，仍会保留运行时的类型信息、`pclntab` 与字符串头数组；逆向时按 Go 的固定布局（string 两字、slice 三字、array 两字、map 运行时函数、栈传参）去读内存，再配合 `go_parser`/`redress` 恢复函数名与类型，就能把 stripped Go 程序还原到接近带符号的可读状态。

## 原理

- **string** 不是 C 的 `\0` 结尾，而是两字结构：
  ```go
  type StringHeader struct { Data uintptr; Len int }
  ```
  看到字符串时先读第二个字取长度，否则 IDA 会一直向后显示直到遇到零字节。
- **slice** 是三字结构 `{Data, Len, Cap}`；**array** 在文章的描述中按 `{Data, Len}` 两字索引。`make([]T, len, cap)` 编译为 `runtime.makeslice`，`make(map)` 为 `makemap`，`new(T)` 为 `newobject`。
- **字符串拼接**：不超过 5 个参数时调用 `runtime.concatstring2..5`，更多时调用 `runtime.concatstrings`；第一个参数是 `*[32]byte` 临时缓冲区，逆向时跳过它，后面的参数才是待拼接的 string 头。
- **类型转换**：`[]byte(s)` 调用 `runtime.stringtoslicebyte`，`string(b)` 调用 `runtime.slicebytetostring`；两者第一个参数同样是缓冲区，后续才是数据指针/长度。
- **map**：创建 `makemap`（常与 `fastrand` 连用）、读取 `mapaccess1`/`mapaccess2`、写入 `mapassign`、遍历 `mapiterinit`/`mapiternext`；后缀可能带类型优化标记。
- **方法**：`func (d *demo) len()` 在汇编中变成普通函数，接收者作为第一个参数；符号名常为 `类型名__方法名` 或 `类型名_方法名`。接收者可能是指针（一字）或值（多字），要看方法定义。
- **调用约定**：传统 Go 通过栈传参和返回值，调用者负责栈空间；参数从左到右、在内存中从下往上写入。函数开头常见 `runtime.morestack*`（伸缩栈），分析时可当作不执行；GC 写屏障 `runtime.gcWriteBarrier` 也可视为未置位分支。
- **协程与 defer**：`go fn()` → `runtime.newproc`；`defer` → `runtime.deferproc` 注册、`runtime.deferreturn` 在返回前执行，顺序为 LIFO。
- **符号恢复**：Go 的反射/接口需要类型信息，`pclntab`（函数名、文件行号）和 `rtype`/`structType`（字段名、偏移、方法表）通常无法完全剥离。`go_parser` 是 IDA 插件，可自动重命名函数、恢复类型和字符串；`redress -s <binary>` 列符号，`redress -t <binary>` 列类型。
- **字符串表扫描**：Go 的字符串常量在 `.rdata` 中以 16 字节的 `{ptr,len}` 头数组存在，IDA 的 Strings 窗口按 C 字符串扫描往往找不到。可以按 16 字节步长读取 `ptr`/`len`，再用 `get_bytes(ptr,len)` 还原；文章给出的脚本就是这种扫描。

## 触发条件

- 目标是 Go 编译的二进制（静态链接、体积大、包含 `runtime.*`/`go.*` 符号或 `Go build ID`）。
- 符号表已被 `-ldflags="-w -s"` 或 garble 等工具处理，但运行时类型信息仍在。
- 需要恢复函数边界、结构体字段、字符串常量或 map/slice 语义来理解算法。
- 有 IDA/Ghidra 等反汇编器，可加载 go_parser 或运行 redress。

## 利用步骤

1. 先确认是 Go：检查 `.gopclntab`、`Go build ID`、`runtime.main`、`main.main` 等特征；用 `redress -s` 快速列出符号。
2. 在 IDA 中运行 `go_parser`，自动恢复函数名、类型和字符串；若没有插件，用 `redress -t` 导出类型信息辅助。
3. 按 Go 布局读数据：遇到字符串先看 `{ptr,len}`；遇到 slice 看三字；遇到 map 操作按 `makemap`/`mapassign`/`mapaccess` 识别键值类型。
4. 在函数开头忽略 `morestack` 分支，在写操作处忽略 `gcWriteBarrier` 的慢路径；按栈传参规则从 `mov [rsp+...], reg` 序列推断参数。
5. 如果字符串窗口缺失，运行 16 字节步进脚本扫描 `.rdata` 的 string header 数组，输出 `地址:内容` 便于交叉引用。
6. 结合 `go tool compile -N -l -S demo.go` 生成的汇编对照理解语法糖（拼接、转换、方法调用）在目标中的形态。

## PoC

```bash
# 关闭优化编译，观察语法对应的汇编
go tool compile -N -l -S demo.go
go build -gcflags="-N -l" demo.go
# 去掉符号/调试信息（逆向方仍可恢复类型信息）
go build -ldflags="-w -s" demo.go

# redress 快速查看符号与类型
redress -s target.exe
redress -t target.exe
```

```python
# IDA 脚本：按 16 字节步进扫描 Go string header 数组
import idaapi
import idc

def scan_strings(start, end):
    r = []
    for i in range(start, end, 16):
        addr = idaapi.get_qword(i)
        size = idaapi.get_qword(i + 8)
        if size > 100:          # 过滤明显不是字符串长度的项
            break
        s = idc.get_bytes(addr, size)
        r.append((i, s))
    return r

strings = scan_strings(0x1c16990, 0x01c19430)
with open("strings.txt", "w") as f:
    for i, s in strings:
        f.write("%x:%s\n" % (i, s))
```

## 变体与关联

- Go 1.17+ 部分平台改用寄存器传参（register ABI），栈布局与老版本不同；需要先确认编译器版本和调用约定。
- garble 会混淆包名/函数名并剥离部分信息，但运行时类型与字符串仍可能残留；可结合动态调试和 `pclntab` 解析。
- 关联：[[code-analysis-reverse-windows-go-dll-init-export-loader-analysis]]（Go DLL 的 init/导出加载分析）、[[ctf-reverse-go-paper-bin-rc4-custom-xxtea-multilayer]]（Go CTF 多层加密逆向实例）。
- 边界：`-ldflags="-w -s"` 只去掉符号表和 DWARF，不等于强混淆；若使用 garble/控制流混淆，仍需动态分析与算法还原。

## 检测与防御

- 检测（逆向方视角）：优先找 Go 特征、`pclntab`、类型信息与 string header 数组；不要只依赖 Strings 窗口。
- 防御（开发方视角）：发布时使用 `-ldflags="-w -s"`，必要时用 garble 做标识符/字符串混淆；不要把密钥、flag、内部 URL 以明文字符串放入二进制；敏感逻辑可放到服务端或做运行时解密。
- 注意：Go 运行时需要类型信息，完全删除会影响反射/接口；防御目标是提高分析成本，而不是追求不可逆。

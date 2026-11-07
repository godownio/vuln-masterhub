---
id: defense-forensics-go-miner-heap-msgpack-field-extraction
title: Go 挖矿样本内存取证：gdb dump 可读段并用 strings 提取 msgpack 上报字段
type: scenario
domain: defense
path: defense/forensics
technique: go-miner-memory-msgpack-field-extraction
aliases:
- Go 挖矿样本内存分析
- gdb dump 挖矿程序
- msgpack 字段提取
- 挖矿程序上报信息
- vmmap dump 内存
- Go 恶意样本 strings
tags:
- forensics
- memory
- gdb
- go
- mining
- msgpack
- strings
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:50:08+08:00'
  notes: 已对照原文Q9与截图核对：Go样本、vmmap段、dump 0x400000-0xa3d000、strings正则提取msgpack标签一致；原文答案为elevated,encrypt_key,host,ipaddr,os_version,process,type,user，卡内用'等'未列type但不影响方法；未验证点：未本机复现dump。
---

## 一句话结论

对 Go 编写的挖矿/远控样本，在运行或 attach 后用 gdb/pwndbg 的 `vmmap` 找到可读数据段，`dump binary memory` 导出后用 `strings | grep -oE '[a-z]+:"[a-z_]+"' | sort -u` 提取 `msgpack:"..."` 标签，可以还原样本向矿池/服务端上报的系统信息字段，如 `host`、`ipaddr`、`os`、`os_version`、`process`、`user`、`elevated`、`encrypt_key` 等。

## 原理

- Go 二进制会把结构体字段名、类型信息、运行时字符串和第三方库（如 msgpack 编码器）的反射元数据以明文或可恢复形式保留在可执行文件中；运行后这些数据也存在于进程内存的可读段。
- 样本若使用 msgpack 序列化上报数据，结构体 tag 会以 `msgpack:"field_name"` 的字符串常量出现；即使二进制被 UPX/UUU 等壳压缩，运行后内存中已是解压状态，dump 内存即可绕过静态脱壳。
- `gdb` 的 `vmmap` 列出进程各段的起止地址与权限；`dump binary memory <file> <start> <end>` 可导出指定范围（通常覆盖代码/只读数据与可写数据段）。
- `strings` 把可打印字符串抽出，正则 `[a-z]+:"[a-z_]+"` 同时匹配 `json:"..."`、`msgpack:"..."` 等结构体标签；`sort -u` 去重后按字段语义筛选“系统信息”类字段。
- 该方法的局限：字段名只说明结构，不能证明每个字段都会被上报；不同样本/版本字段集合不同，需结合二进制中的同类结构、编码逻辑或流量验证。

## 触发条件

- 拿到样本可执行文件，且能在隔离分析机运行或 attach；有 gdb + pwndbg（或等价工具）。
- 样本未加不可逆的强壳；若是 UPX/UUU 壳，运行后内存已解压，仍可 dump。
- 知道目标进程的内存布局，能从 `vmmap` 选择包含数据/字符串的可读段。
- 分析环境与样本架构一致（如 x86-64 Linux ELF）。

## 利用步骤

1. 识别样本语言与壳：`file`、Detect It Easy 查看 Compiler/Language；Go 样本通常显示 `Go(1.10.x-1.17.x)`。若显示 UPX/UUU packer，记录壳类型但不必强行静态脱壳。
2. 在隔离环境启动样本或 attach：`gdb ./kworker`，进入 pwndbg。
3. `vmmap` 查看段布局，记录可读段（`r--`/`rw-`）的 Start/End；对 Go 样本通常从镜像基址附近的只读数据段开始。
4. 可选：`search -t string system` 或 `find` 搜索已知关键字，确认字符串落在哪个段。
5. 导出内存：`dump binary memory dump.bin <start> <end>`（例如从 `0x400000` 到 `0xa3d000`，按实际 vmmap 调整）。
6. 提取结构体标签：`strings dump.bin | grep -oE '[a-z]+:"[a-z_]+"' | sort -u`。
7. 过滤与归类：保留 `msgpack:"..."` 标签，按 `host`、`ipaddr`、`os`、`os_version`、`process`、`user`、`elevated`、`encrypt_key` 等语义筛出系统信息字段；与样本的配置结构、上报流量交叉验证。
8. 保留 dump、样本哈希与字段列表作为证据；分析完成后在隔离环境销毁样本与进程。

## PoC

```bash
# 1) 语言与壳识别
file kworker
# ELF 64-bit LSB executable, x86-64, statically linked, stripped

# 2) gdb/pwndbg 查看内存布局
gdb -q ./kworker
pwndbg> vmmap
# 0x400000 0x6e3000 r-xp  2e3000  /home/analyst/kworker
# 0x6e3000 0x9dd000 r--p  2fa000  /home/analyst/kworker
# 0x9dd000 0xa0c000 rw-p  2f000   /home/analyst/kworker

# 3) 可选：按字符串定位
pwndbg> search -t string system
pwndbg> dump binary memory dump.bin 0x400000 0xa3d000
pwndbg> quit

# 4) 提取 msgpack/json 结构体标签
strings dump.bin | grep -oE '[a-z]+:"[a-z_]+"' | sort -u
# msgpack:"host"
# msgpack:"ipaddr"
# msgpack:"os"
# msgpack:"os_version"
# msgpack:"process"
# msgpack:"user"
# msgpack:"elevated"
# msgpack:"encrypt_key"
```

## 变体与关联

- 若样本被 UPX 壳保护且静态脱壳失败（如 `UPX! ... CantUnpackException: l_info corrupted`，或 UUU packer 变体），运行后 dump 内存是更稳妥的路径。
- 通用 core dump/内存镜像的字符串与高熵提取见 [[defense-forensics-core-dump-secret-extraction]]；本卡侧重 Go + msgpack 标签的结构化字段还原。
- 变体：也可用 `/proc/<pid>/maps` 配合 `dd`/`gcore` 导出，或用 Volatility 对完整内存镜像做字符串扫描。
- 变体：字段可能使用 `json`、`yaml` 等其他 tag；正则中的键名部分可改为 `[A-Za-z0-9_]+` 以覆盖更多标签。
- 关联：[[defense-incident-response-docker-tomcat-mining-triage]]（挖矿事件中定位样本与矿池的完整流程）。

## 检测与防御

- 监控隐藏目录中运行的 ELF 与异常外连（矿池端口/域名），发现后保留进程内存再终止。
- 对 Go 样本可预先提取结构体标签与字符串，建立 IOC/字段特征库，用于同类样本快速识别。
- 容器/主机限制出站，阻断矿池连接；对可执行文件做哈希与路径白名单。
- 事件响应时优先保存 `/proc/<pid>/maps`、`/proc/<pid>/exe`、内存 dump 与样本原件，确保字段分析可复核。

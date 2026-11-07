---
id: code-analysis-reverse-windows-remcos-settings-config-extraction
title: Remcos RAT SETTINGS 资源提取：RC4 与 0x7C1E1E1F7C 分隔的配置字段解析
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: remcos-config-extraction
tags:
- windows
- remcos
- rat
- config-extraction
- pe-resource
- rc4
- malware-analysis
- go
- ioc
cve: []
severity: medium
confidence: high
affected_versions: Remcos v7.2.5 Light（原文分析版本；其他版本字段映射可能变化）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T20:00:20+08:00'
  notes: 已对照原文及全部37张图核对：.rsrc 定位与 OffsetToData-rva+raw 换算、SETTINGS 资源1333B、首字节key_len+RC4、7C1E1E1F7C 分隔、字段ID映射(0/1/2/41/3/4/5/8/9/48/10/39/14/15/16/49/17/20/21/22/24/25/26/35/36/37/38/54/55/56)与图35-37输出一致；示例 C2 146.19.24.131:2404、RemoteHost、Rmc-JV4XWU、Remcos、remcos.exe、Screenshots、MicRecords、TLS 证书/私钥均与截图吻合。小瑕疵：原理中'第 N 段对应第 N 个配置项'表述不准确，实际是按字段ID索引 datas[field.ID]（ID非连续）。affected_versions 保留原文分析版本 Remcos v7.2.5 Light（映射具有版本相关性）。未验证点：脚本未本机运行；样本未执行；frontmatter无sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-remcos-settings-config-extraction/
draft: false
kb_aliases:
- Remcos 配置提取
- Remcos SETTINGS 资源
- Remcos RC4 解密
- 7C1E1E1F7C
- 远控配置解析
- Remcos 字段映射
---

## 一句话结论

Remcos RAT 把配置以 RC4 加密后存放在 PE 的 `SETTINGS` 资源中，格式为“1 字节密钥长度 + 密钥 + 密文”，解密后的明文用 `7C 1E 1E 1F 7C` 分隔成字段；按字段 ID 与 Remcos Builder 选项的对应关系解析，即可一键提取 C2 地址/端口、互斥量、安装路径、键盘记录/截屏/录音配置以及 TLS 证书与私钥。

## 原理

- **资源定位**：解析 PE 节表，找到 `.rsrc` 的 `VirtualAddress` 与 `PointerToRawData`；遍历资源目录，找到类型为 `SETTINGS` 的资源项，读取其 `OffsetToData` 与 `Size`。资源数据在文件中的偏移为 `OffsetToData - rsrc_VirtualAddress + rsrc_PointerToRawData`。
- **加密格式**：资源首字节是 RC4 密钥长度 `key_len`，随后 `key_len` 字节是密钥，剩余全部是密文；用 RC4 解密后得到配置明文。
- **字段分隔**：明文按 `7C 1E 1E 1F 7C` 分割，第 N 段对应 Builder 中第 N 个配置项。不同版本/不同构建选项的段数与字段 ID 可能变化，需用同版本 Remcos 生成多组样本对比确认。
- **字段语义**：示例映射包括连接 TLS（C2 `ip:port`）、AssignedName、连接间隔/延迟、安装与启动项（CurrentUserRun/LocalMachineRun/ExplorerRun）、安装目录与文件名、提权、互斥量、键盘记录、截屏触发与目录、离线录音目录、TLS client/server 证书与私钥等。
- **交叉验证**：Remcos Builder 的 `BuilderProfiles/DefaultProfile.ini` 与 `tls/remcos_client.key`、`tls/remcos_server.key` 内容与解密出的配置一致，可用于确认字段映射是否正确。
- **样本形态**：记忆中的 Remcos 可能由外层加载器（如 MSI → 签名 EXE → 侧加载 DLL → 内存 PE）释放，需先从内存 dump 出内层 PE，再按上述资源格式提取。

## 触发条件

- 样本为 Remcos RAT（或其内存 dump），且包含 `SETTINGS` 资源；
- 配置使用“1 字节密钥长度 + RC4 密钥 + 密文”的格式（不同版本可能变化）；
- 已知或能推断字段分隔符 `7C 1E 1E 1F 7C` 与字段 ID 映射；
- 需要离线分析样本，不要求样本可执行。

## 利用步骤

1. 从样本或内存 dump 中取得内层 PE（若是外层加载器，先定位并 dump 内存中的 MZ/PE）。
2. 解析 PE 节表，定位 `.rsrc` 的 `VirtualAddress`、`PointerToRawData`。
3. 遍历资源目录，找到 `SETTINGS` 资源，按 `OffsetToData/Size` 从文件中切出加密配置。
4. 读取首字节 `key_len`，取 `key = data[1:1+key_len]`，`cipher = data[1+key_len:]`。
5. RC4 解密 `cipher`，按 `7C 1E 1E 1F 7C` 分割明文。
6. 按字段 ID 映射输出配置项；重点记录 C2 `ip:port`、TLS 开关、互斥量、安装目录/文件名、启动项、键盘记录/截屏/录音配置、证书与私钥。
7. 用同版本 Remcos Builder 的 `DefaultProfile.ini` 或 `tls/*.key` 交叉验证字段映射。

## PoC

Go 核心骨架（资源提取 + RC4 + 分隔 + 字段映射）：

```go
package main

import (
    "bytes"; "crypto/rc4"; "encoding/hex"; "fmt"; "os"
    "github.com/saferwall/pe"
)

var fields = map[int]string{
    0: "Connection:TLS", 1: "AssignedName", 2: "ConnectionInterval",
    41: "ConnectionDelay", 3: "InstallRemcos", 4: "CurrentUserRun",
    5: "LocalMachineRun", 8: "ExplorerRun", 9: "InstallFolderID",
    48: "InstallSubfolder", 10: "InstallFileName", 39: "Elevate",
    14: "Mutex", 15: "KeyloggerMode", 16: "LogFolderID", 49: "LogSubfolder",
    17: "LogFileName", 20: "ScreenTimeTrigger", 21: "ScreenTimeMinutes",
    22: "ScreenWindowTrigger", 24: "ScreenWindowSeconds",
    25: "ScreenFolderID", 26: "ScreenFolderName",
    35: "RecordAudio", 36: "AudioMinutes", 37: "AudioFolderID",
    38: "AudioFolderName", 54: "ClientCert", 55: "ClientKey", 56: "ServerCert",
}

func main() {
    f := os.Args[1]
    p, _ := pe.New(f, &pe.Options{}); p.Parse()
    var rva, raw uint32
    for _, s := range p.Sections {
        if s.String() == ".rsrc" { rva, raw = s.Header.VirtualAddress, s.Header.PointerToRawData }
    }
    var data []byte
    for _, t := range p.Resources.Entries {
        if t.Directory.Entries[0].Name == "SETTINGS" {
            d := t.Directory.Entries[0].Directory.Entries[0].Data.Struct
            off := d.OffsetToData - rva + raw
            all, _ := os.ReadFile(f)
            data = all[off : off+d.Size]
            break
        }
    }
    n := int(data[0]); key := data[1 : 1+n]; ct := data[1+n:]
    c, _ := rc4.NewCipher(key); pt := make([]byte, len(ct)); c.XORKeyStream(pt, ct)
    parts := bytes.Split(pt, []byte{0x7C, 0x1E, 0x1E, 0x1F, 0x7C})
    for id, name := range fields {
        if id < len(parts) { fmt.Printf("%d %s:\n%s\n", id, name, hex.Dump(parts[id])) }
    }
}
```

示例输出（节选）：字段 0 得到 `146.19.24.131:2404:1`，字段 1 为 `RemoteHost`，字段 14 为 `Rmc-JV4XWU`，字段 48 为 `Remcos`，字段 10 为 `remcos.exe`，字段 26 为 `Screenshots`，字段 38 为 `MicRecords`，字段 54-56 为 TLS 证书/私钥。

## 变体与关联

- **版本差异**：Remcos Builder 版本升级后字段 ID、分隔符或加密格式可能变化；必须用同版本 Builder 生成样本做对照，不能直接套用旧映射。
- **样本形态**：配置可能位于内存 PE 而非磁盘文件；外层加载器（MSI → 签名 EXE → `nethost.dll` 侧加载 → 内存 PE）释放的 Remcos 需先 dump 内层 PE。
- **交叉验证**：`BuilderProfiles/DefaultProfile.ini`、`tls/remcos_client.key`、`tls/remcos_server.key` 与解密配置一致，可用于校验。
- 关联：PE 资源解析、RC4 配置解密、远控样本 IOC 提取、内存 PE dump。
- 边界：本卡是分析提取技术，不是利用链；不同家族/版本不能直接复用字段映射。

## 检测与防御

- 检测：对样本 PE 的 `SETTINGS` 资源做 YARA 规则；监控 RC4 解密后出现 `7C 1E 1E 1F 7C` 分隔特征；对远控配置中的 C2 `ip:port`、互斥量、安装路径建立 IOC。
- 检测：内存扫描查找 `SETTINGS` 资源或解密后的明文配置；结合外层加载器行为（MSI 释放、Run 键、DLL 侧加载、内存 PE）做关联告警。
- 防御：封锁提取出的 C2 地址/端口与域名；监控配置中的互斥量、安装目录、启动项；对 Remcos 常见资源名与 RC4 配置格式做静态查杀。
- 处置：提取配置用于溯源与影响面评估；不要运行样本，分析应在隔离环境进行。

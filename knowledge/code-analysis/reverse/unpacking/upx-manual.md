---
id: code-analysis-reverse-unpacking-upx-manual
title: UPX 壳的手动脱壳流程
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: upx-unpacking
aliases: [UPX unpack, UPX 脱壳, 手动脱壳]
tags: [reverse, unpacking, upx, elf, pe]
cve: []
severity: medium
confidence: high
status: draft
created: 2026-11-04
updated: 2026-11-04
---

## 一句话结论

UPX 是压缩壳，通常在入口点解压原始镜像并跳回 OEP；找到 OEP 后 dump 内存并修复导入表即可还原可分析的程序。

## 原理

UPX 把原程序压缩后附加解压 stub，程序入口先执行 stub，在内存中还原原始 section，再跳转到原始入口点（OEP）。脱壳的关键是定位这段跳转与还原后的内存布局。

## 触发条件

- 样本可识别为 UPX（section 名 `UPX0`/`UPX1`、特征字符串、`upx -l` 可识别）；
- 允许动态调试或内存 dump；
- 有可用的导入表修复工具。

## 利用步骤

1. 用 `upx -l`、`strings`、section 名确认 UPX；
2. 在调试器中运行到解压 stub，观察内存写入与跳转；
3. 在 OEP 处暂停，dump 进程内存；
4. 修复 IAT、重建 section，验证程序可运行；
5. 对还原后的二进制做静态分析。

## PoC

```bash
upx -l sample.exe
# 调试器中在 OEP 处 dump，再用 Scylla/ImpRec 修复 IAT
```

## 变体与关联

- 变体：UPX 改壳、加花指令、修改 section 名；
- 关联：其它压缩壳/加密壳的 ESP 定律与内存断点。

## 检测与防御

- 检测：UPX section 名、stub 特征、异常入口；
- 防御：加壳不是安全边界，敏感逻辑应配合完整性校验与反调试。

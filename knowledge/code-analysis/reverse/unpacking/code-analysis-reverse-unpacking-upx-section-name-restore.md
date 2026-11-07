---
id: code-analysis-reverse-unpacking-upx-section-name-restore
title: 改版 UPX 区段名还原：SAUY/YSYY/C4RP 改回 UPX0/UPX1/UPX2 后用 upx -d 脱壳
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: modified-upx-section-name-restore
aliases:
- 改版 UPX
- UPX 区段名修改
- SAUY YSYY C4RP
- upx -d 失败
- 010 Editor 改区段名
- UPX 区段还原
- NSSCTF Ultimate Packer
tags:
- reverse
- upx
- unpacking
- pe
- section-name
- 010-editor
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V197
  verified_at: '2026-11-06T22:44:58+08:00'
  notes: 已对照原文及图06-10核对：Die识别UPX(3.91+)[modified]、区段名SAUY/YSYY/C4RP改回UPX0/UPX1/UPX2、UPX 5.0.2解压63642→45210(71.04%)均与截图一致；未本机复跑UPX。
---

## 一句话结论

样本被 UPX 加壳但区段名被改成 `SAUY`/`YSYY`/`C4RP` 等非标准名称，导致 `upx -d` 直接拒绝脱壳；在 010 Editor 中把区段名改回 `UPX0`/`UPX1`/`UPX2`（并保留/修正 `UPX!` 标记）后，标准 `upx -d` 即可正常解压，得到原始程序。

## 原理

- UPX 在 PE 头中通过区段名（通常 `UPX0`、`UPX1`、`UPX2`）和 `UPX!` 标记识别自己的壳；`upx -d` 会先验证这些特征与压缩数据布局，不匹配就报 “not packed by UPX” 或直接失败。
- 改版/保护器只改区段名（或大小写、顺序、附加段）就能让标准 UPX 工具拒绝处理，但压缩算法、stub 与解压逻辑往往仍是原版；因此把区段名恢复后，工具即可按正常流程解压。
- 本例 `Die` 仍识别为 `UPX(3.91+)[modified]`，区段表为 `SAUY/YSYY/C4RP`；用 010 Editor 查看并修改 PE 区段表字符串，把 `SAUY→UPX0`、`YSYY→UPX1`、`C4RP→UPX2`，保存后 `upx -d` 成功。
- 为什么可行：区段名是 PE 节表中的 8 字节名称字段，不参与解压算法本身；标准 UPX 只依赖名称/标记做入口判断，恢复名称即满足其前置检查。
- 若修改的不只是名称（还改了 stub、压缩数据、入口或节表布局），单纯改名会失败，需要改用 Unicorn 仿真/手动 dump + IAT 重建（见关联卡）。

## 触发条件

- 样本被 UPX 或改版 UPX 加壳，`Die`/PEiD 识别为 UPX（可能带 [modified]）。
- `upx -d` 报错/拒绝，PE 节表中的区段名不是标准 `UPX0/UPX1/UPX2`，但存在 `UPX!` 字符串/特征。
- 可读写 PE 文件的十六进制编辑器（010 Editor、CFF Explorer、pefile 脚本）。
- 加壳器只改了区段名，未改压缩数据/stub。

## 利用步骤

1. 用 `Die`/PEiD 查壳，记录 “UPX(3.91+)[modified]” 之类的结论。
2. 用 010 Editor 打开样本，定位 PE 节表（`IMAGE_NT_HEADERS` 后紧跟 `IMAGE_SECTION_HEADER` 数组），查看各节的 8 字节 Name。
3. 将非标准名称改回 UPX 默认：`SAUY→UPX0`、`YSYY→UPX1`、`C4RP→UPX2`；如名称长度不足用 `\0` 补齐，不要改动其他节表字段。
4. 确认文件中仍存在 `UPX!` 标记；若标记也被改名/破坏，可一并恢复（注意不要破坏压缩数据）。
5. 保存修改后的文件，执行：

```bash
upx -d modified.exe -o unpacked.exe
```

6. 用 `Die`/PEiD 复查 `unpacked.exe` 不再是 UPX，拖入 IDA 分析原始逻辑。
7. 若 `upx -d` 仍失败，检查节表 `VirtualSize/RawSize`、入口点、`UPX!` 偏移是否被改；必要时改用 Unicorn 仿真 stub 或手动 dump。

## PoC

```text
# 原始节表（010 Editor 观察）
Name: SAUY   (应为 UPX0)
Name: YSYY   (应为 UPX1)
Name: C4RP   (应为 UPX2)
# 修改后
Name: UPX0 / UPX1 / UPX2
```

```bash
upx -d upxxx!.exe -o upxxx!.unpacked.exe
# 输出：Unpacked 1 file.
```

原文样本 `upxxx!.exe` 修改区段名后，UPX 5.0.2 正常解压（63642 → 45210 字节，71.04%），随后 IDA 可见 `main` 与加密校验逻辑。本卡未复跑；不同 UPX 版本的区段名/标记校验可能不同。

## 变体与关联

- 仅改大小写/顺序：如 `upx0/upx1`、`UPX1/UPX0`；恢复为工具期望的标准名称与顺序。
- 改 `UPX!` 标记：在文件中搜索并恢复 ASCII `UPX!`（注意可能是压缩数据的一部分，需确认位置）。
- 改 stub/压缩数据：单纯改名无效，需走 Unicorn 仿真脱壳（`code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation`）或手动 dump + IAT 重建。
- 其他壳：ASPack/PECompact/Themida 的区段名/入口伪装同理，但解压算法不同，不能直接套用 `upx -d`。
- 关联卡：花指令修复（`code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair`）；DLL 内存 dump（`code-analysis-reverse-unpacking-dll-aplib-virtualalloc-protect-dump`）。

## 检测与防御

- 这是逆向/脱壳技术，不是攻击；防御方应关注样本的加壳/改版特征（非标准区段名、UPX! 残留、入口在数据段）。
- 恶意样本常用改版 UPX 规避自动化沙箱/静态工具；检测应结合节表异常、入口点、导入表与 stub 特征，而不只看区段名。
- 对合法软件：加壳/改名只能提高分析成本，不能作为安全边界；关键逻辑仍应服务端校验/混淆/完整性保护。

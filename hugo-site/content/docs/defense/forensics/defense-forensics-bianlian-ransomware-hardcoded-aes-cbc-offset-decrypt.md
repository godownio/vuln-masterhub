---
id: defense-forensics-bianlian-ransomware-hardcoded-aes-cbc-offset-decrypt
title: BianLian 勒索软件解密：硬编码 AES-CBC KEY/IV + 每样本加密偏移，desktop.ini 已知明文匹配密钥，按文件大小分块逆向恢复
type: scenario
domain: defense
path: defense/forensics
technique: bianlian-ransomware-hardcoded-aes-cbc-offset-decrypt
tags:
- ransomware
- bianlian
- forensics
- recovery
- aes-cbc
- known-plaintext
- golang
- malware-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V463
  verified_at: '2026-11-10T15:09:40+08:00'
  notes: 已对照原文与23/23图核实：Go 样本(go1.18.3)、A-Z 盘遍历、Look at this instruction.txt(990)、.bianlian 原地 WriteAt 加密+FileRename、.data 内 KEY 633A56D0... 与 IV FC55A60A...、CalcBlock(size/4096<<12 + 0x400000 魔数特判/封顶/最小16)、GetBlocksAmount 第一层校验、ReadAt==blockSize 第二层校验、小文件16字节逐块/大文件整块 CBC、desktop.ini.bianlian 已知明文匹配 key(检查 UTF-16LE system32)、578 文件恢复仅3个MD5不同，均与原文/图一致。5 组样本参数与原文表格逐字核对一致。与 PyInstaller 内嵌 RSA 私钥、BlackBasta 官方解密器、CryptNet RSA 封装等恢复链不同，非重复。原文未标组件版本（仅样本哈希与 go1.18.3 构建信息），不设 affected_versions；无 sources 字段；path 合法。dup-scan(11-08)早于建卡。
url: /docs/defense/forensics/defense-forensics-bianlian-ransomware-hardcoded-aes-cbc-offset-decrypt/
draft: false
kb_aliases:
- BianLian 解密
- 边连勒索软件
- BianLian 加密原理
- AES CBC 硬编码密钥
- 每样本加密偏移
- desktop.ini 已知明文
- .bianlian 文件恢复
---

## 一句话结论

BianLian（Go 编写）样本把 AES-CBC 的 KEY/IV 与“加密起始偏移”硬编码在自身数据段中，且加密前有两层校验决定哪些文件/区间真正被加密；拿到对应样本后，可用 `desktop.ini.bianlian` 这类内容可预期的文件作为已知明文，从多组内置 key/IV/offset 中识别出正确组合，再按“小文件按 16 字节块逐块解密 / 大文件按计算出的块整体解密 / 未加密文件原样复制”的逻辑逆序处理，即可恢复绝大多数 `.bianlian` 文件（文章工具恢复 578/578，仅 3 个系统运行中被修改的文件 MD5 不同）。

## 原理

- **样本行为**：遍历 A 到 Z 盘 → 在各目录投放 `Look at this Instruction.txt` 勒索说明（Tox 联系方式、受害者 ID、10 天后在 onion 泄漏站公开数据的威胁）→ 对文件原地“读块-加密-写回”并加 `.bianlian` 后缀。因为直接改写原始文件，未加密区间与已加密数据混在同一文件中，常规“删除文件后数据恢复”不可用，只能靠算法逆向解密。
- **算法**：AES-CBC。KEY（32 字节）与 IV（16 字节）以字节数组硬编码在 `.data` 段，不同样本不同；每个样本另有一个硬编码“加密偏移位置”（从文件该偏移处开始加密）。文章提取的 5 个样本参数（哈希前缀 → 偏移 / KEY / IV）：
  - `1fd07b8d...` → offset 9；KEY `633A56D0388869237C8DA6B7FC09F55DF35408C332614F692D11222583B36B62`；IV `FC55A60A25B0472CFC2C6EBC3DD89DAB`
  - `3a2f6e61...` → offset 1；KEY `26DD1B400AED80B0980B34BAD76D3BE6599123FA562266B421A14AC8E02ECFA3`；IV `D518BA928469306D579D625F56D09883`
  - `46d340ea...` → offset 0x34；KEY `979412FF08F7D2F0BD5F7E7E2A4919E9BF68CC7AABAB499872EC822DDCDA5307`；IV `0FC14323F7A13CCA0569EBCFAE283996`
  - `af46356e...` → offset 0x41；KEY `4A4105960D2C127D9711AC851BC1F10D17471B5A184CCDADA79003DA82CFDBA2`；IV `5560E19D4B425420F6F5EF387D97065A`
  - `eaf5e26c...` → offset 0x3d；KEY `27CFAE34A83C9A7E48060E18A68A233914271DB7D414C838FB1EAEAEA89E5CDE`；IV `223B67AC534F9938CC7B1F9777A95840`
- **块大小计算**：`block = (fileSize / 0x1000) << 12`；若 `fileSize > 0x400000`，用魔数乘法（`0xCCCCCCCCCCCCCCCD`）计算后再取整到 0x1000 的倍数，并封顶 0x400000；结果小于 16 时按 16。
- **两层校验（决定是否加密）**：
  1. `GetBlocksAmount(fileSize, blockSize, offset)` 返回值 > 0 才继续（该函数按文件大小/块大小/偏移做复杂比例计算，样本里是 `project1_common_GetBlocksAmount`）。
  2. 从 `offset` 开始实际读取 `blockSize` 字节，若读满（返回值 == blockSize）才调用加密。
  因此同一批 `.bianlian` 文件里存在“只是改了后缀、内容并未加密”的文件：例如实测 0x1000–0x1008 大小不加密、0xfff 按小块加密、0x1009 起按大块整体加密、0x400000 不加密。
- **加密/解密形态**：
  - 小文件（`fileSize < 0x1000`）：从 offset 起按 16 字节为一个块，逐块用同一 IV 做 AES-CBC 单块加/解密；尾部不足 16 字节的部分保持原样。
  - 大文件：把 `[offset, offset+blockSize)` 整段作为一个 CBC 链加/解密，段后内容原样保留；若 `offset+blockSize > fileSize` 则不解密该段。
  - 未通过校验的文件：原样复制内容，仅改回原文件名。
- **密钥识别（已知明文）**：`desktop.ini` 是 Windows 桌面必然存在的文件，内容可预期；样本会把它加密成 `desktop.ini.bianlian`。用 5 组内置 key/IV/offset 逐一按其块逻辑解密，检查明文是否包含 UTF-16LE 的 `system32` 等特征，命中即确定了该样本的参数，再批量处理全盘 `.bianlian` 文件。
- **为什么可恢复**：密钥、IV、偏移都在样本内；算法为确定性对称加密；未加密文件与未加密区间保持明文；两层校验还意外留下了“跳过加密”的文件。限制是必须拿到对应样本/参数，且加密期间被系统改写的文件无法还原到最初字节。

## 触发条件

- 主机被 BianLian 样本加密，磁盘上存在 `.bianlian` 文件、`Look at this Instruction.txt` 与 `desktop.ini.bianlian` 等残留。
- 能取得与本次攻击匹配的样本（用于提取 KEY/IV/offset），或已知属于上述 5 组参数之一。
- 加密后文件系统未被进一步破坏（未格式化/覆盖），文件内容仍为原始+加密区间。
- 分析环境安全（样本为 Windows PE，需隔离运行/仅静态提取参数）。

## 利用步骤

1. **识别**：全盘搜索 `.bianlian`、`Look at this Instruction.txt`；确认勒索说明中的 Tox ID/邮箱/onion 地址与 BianLian 特征一致；用 strings/DIE 确认样本为 Go（如 `go1.18.3`）。
2. **取参数**：静态分析样本，在 `.data` 段定位 AES KEY（32 字节）、IV（16 字节）与硬编码加密偏移；或直接使用本文提供的 5 组参数逐一尝试。
3. **匹配密钥**：以 `desktop.ini.bianlian` 为参考文件，对每组参数按第 5 步逻辑试解密，检查结果是否包含可读内容/UTF-16LE `system32` 等特征；命中则锁定该组。
4. **枚举待恢复文件**：用 Everything 等工具导出全部 `.bianlian` 文件列表（文章用 `C:\Users\admin\Desktop\11.txt`）。
5. **逐文件解密**：
   - 计算 `blockSize = CalcBlock(fileSize)`；
   - 若 `GetBlocksAmount(fileSize, blockSize, offset) > 0`：
     - `fileSize < 0x1000`：拷贝 `[0, offset)`，从 offset 起以 16 字节为块逐块 AES-CBC 解密，尾部落单字节原样拼接；
     - 否则：拷贝 `[0, offset)`，对 `[offset, offset+blockSize)` 整段 CBC 解密（若越界则不解密），再拼接剩余部分；
   - 若校验不通过：原样复制文件内容；
   - 写入去掉 `.bianlian` 的原文件名，并将原加密文件重命名为 `.bak`。
6. **校验**：与备份/镜像对比 MD5；文章案例 578 个文件全部恢复，3 个因加密时系统正在修改而 MD5 不同。
7. **善后**：保留原始 `.bianlian` 样本与样本文件以便复核；对泄漏数据、横向痕迹与 ProxyShell/ SonicWall 等入口做应急排查。

## PoC

```go
// 核心解密逻辑（按文章 Go 实现整理，省略错误处理）
func DecryptAES(ct, key, iv []byte) []byte { // ct 长度须为 16 的倍数
    block, _ := aes.NewCipher(key)
    out := make([]byte, len(ct))
    cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
    return out
}

func decryptFile(fileData []byte, key, iv []byte, offset int, fileSize int64) []byte {
    blockSize := CalcBlock(fileSize)          // 见文章 common.go 的 (size/0x1000)<<12 + 0x400000 特判
    out := []byte{}
    if GetBlocksAmount(fileSize, blockSize, int64(offset)) <= 0 {
        return fileData                        // 未加密，原样
    }
    if fileSize < 0x1000 {                     // 小文件：16 字节逐块
        if int64(offset)+blockSize > fileSize { return fileData }
        out = append(out, fileData[:offset]...)
        n := (fileSize - int64(offset)) / 16
        for i := int64(0); i < n; i++ {
            out = append(out, DecryptAES(fileData[offset+16*i:offset+16*(i+1)], key, iv)...)
        }
        out = append(out, fileData[int64(offset)+n*16:]...)
    } else {                                   // 大文件：整块 CBC
        out = append(out, fileData[:offset]...)
        if int64(offset)+blockSize > fileSize {
            out = append(out, fileData[offset:]...)
        } else {
            out = append(out, DecryptAES(fileData[offset:offset+int(blockSize)], key, iv)...)
            out = append(out, fileData[offset+int(blockSize):]...)
        }
    }
    return out
}
```

```text
// 已知明文选密钥（文章思路）
对每组 (key, iv, offset):
  解密 desktop.ini.bianlian
  若结果包含 UTF-16LE 的 "system32"（字节 73 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00）→ 命中该组参数
```

说明：以上为按文章 Go 工具整理的等价逻辑，未在真实受害者数据上执行；`CalcBlock`/`GetBlocksAmount` 的完整实现见文章代码。

## 变体与关联

- **同族加密缺陷**：硬编码密钥 + 固定 IV + 确定性 CBC、以及“部分文件/部分区间未加密”是可恢复性的核心；遇到类似勒索样本时，优先找 key/IV/offset、已知明文和跳过加密的分支。
- **其他勒索恢复案例**：PyInstaller 勒索样本把 RSA 私钥打包导致可解密，见 [[defense-forensics-pyinstaller-ransomware-embedded-rsa-aes-ecb-recovery]]；固定 AES key/IV 的字段解密见 [[defense-forensics-config-aes-key-iv-database-field-decrypt]]。
- **入口与横向**：BianLian 利用 ProxyShell（CVE-2021-34473/CVE-2021-34523/CVE-2021-31207）与 SonicWall VPN 漏洞进入，使用 nssm.exe/ngrok 等 LotL 工具与 RDP/WinRM/WMI/PowerShell 横向；应急时应同时排查这些入口（相关 Exchange/ProxyShell 利用可另查本库）。
- **变体**：不同样本的 offset/KEY/IV 不同；后续版本可能改为随机 key 或加入 RSA 封装，一旦密钥不在样本内，本文方法失效，只能依赖厂商解密器/密钥泄露/备份。

## 检测与防御

- **检测**：全盘出现 `Look at this Instruction.txt`、`.bianlian` 后缀、`desktop.ini.bianlian`；Go 程序遍历 A-Z 盘并对文件原地读写、同目录创建勒索说明；勒索说明含 Tox ID/onion 泄漏站；样本 `.data` 段含 32 字节 key 与 16 字节 IV 常量。
- **防御**：及时修补 ProxyShell/SonicWall 等边界漏洞；禁用/限制 nssm、ngrok 等工具滥用；最小权限与网段隔离；离线/不可变备份（3-2-1）是应对勒索的根本。
- **响应**：隔离主机、保留内存与磁盘镜像；提取样本与 `.bianlian` 文件离线解密；统计影响范围、核查数据外泄与横向；轮换凭据并修复入口。
- **法律与授权**：解密仅用于受害方数据恢复与取证，需在授权范围内进行；不要运行未知样本于生产环境。

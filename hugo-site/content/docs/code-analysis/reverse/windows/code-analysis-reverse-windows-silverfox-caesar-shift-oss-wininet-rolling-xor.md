---
id: code-analysis-reverse-windows-silverfox-caesar-shift-oss-wininet-rolling-xor
title: 银狐母体 C2 取址链：URL 字母位移 -11 还原 OSS 地址 + WinInet 下载 + 4 字节滚动密钥解密
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: silverfox-caesar-url-wininet-rolling-xor
tags:
- windows
- silverfox
- malware-analysis
- c2
- url-obfuscation
- caesar-shift
- wininet
- rolling-xor
- config-decrypt
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V307
  verified_at: '2026-11-08T12:08:54+08:00'
  notes: 已对照原文与图26-32核对：图27 strcpy(seeadd://zdd-4.zdd-ny-slyrkszsf.lwtjfynd.nzx/n.ole) + key=11 + sub_861D 校验 945895776；图28 大小写字母 (c-base-k+26)%26 回退循环；图29 x64dbg 0x13C480 解密出 https://oss-4.oss-cn-hangzhou.aliyuncs.com/c.dat；图30 WinInet InternetOpenA/OpenUrlA/ReadFile/CloseHandle + Sleep/HeapAlloc/HeapFree 与 while(!v10&&v20<100)、dwFlags=0x80000000；图31 v4=1254685213 滚动异或 v4=v3|(v4<<8)（v3 为原始密文）；图32 IOC 哈希/域名/URL，均与卡片一致。URL 逐字符位移验证可完整还原；卡片 PoC 的 Python 滚动异或按原始密文更新，与反编译顺序一致。未验证点：远程 c.dat 已失效，未用真实密文验证解密输出（卡片已注明）。dedup 仅自身 duplicate，无 related；dup-scan 无本卡 pair。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-silverfox-caesar-shift-oss-wininet-rolling-xor/
draft: false
kb_aliases:
- seeadd://
- 银狐 URL 凯撒位移
- 字母表回退 11 位
- oss-4.oss-cn-hangzhou.aliyuncs.com/c.dat
- 4 字节滚动密钥异或
- 银狐远程配置下载
---

## 一句话结论

银狐母体把 C2 URL 以 `seeadd://zdd-4.zdd-ny-slyrkszsf.lwtjfynd.nzx/n.ole` 的形式硬编码，解密函数对字母按字母表回退 11 位、非字母保持不变，还原出 `https://oss-4.oss-cn-hangzhou.aliyuncs.com/c.dat`；随后用 WinInet（`InternetOpenA`/`InternetOpenUrlA`/`InternetReadFile`）循环下载，最后用初值 `1254685213`（`0x4AC8FA1D`）的 4 字节滚动密钥逐字节异或解密下载数据。

## 原理

- **URL 字母位移**：解密函数遍历字符串，对 `A-Z` 与 `a-z` 分别执行 `(c - base - key + 26) % 26 + base`，`key=11`；数字、`.`、`:`、`/`、`-` 等非字母不变。因此 `seeadd` → `https`、`zdd` → `oss`、`zdd-ny-slyrkszsf` → `oss-cn-hangzhou`、`lwtjfynd` → `aliyuncs`、`nzx` → `com`、`n.ole` → `c.dat`，整串还原为阿里云 OSS 上的 `c.dat`。这是单表凯撒替换，密钥空间只有 26，静态看到 `seeadd://`/`oss` 形态即可直接离线还原。
- **为什么用弱混淆**：样本需要在运行时把明文 URL 交给网络 API，无法使用不可逆哈希；单表位移足以避免明文 URL 出现在字符串表/静态规则中，且实现只有十几行循环，体积极小。
- **WinInet 下载**：解密后代码动态解析 `wininet.dll` 的 `InternetOpenA`、`InternetOpenUrlA`、`InternetReadFile`、`InternetCloseHandle`，以及 `kernel32.dll` 的 `Sleep`、`GetProcessHeap`、`HeapAlloc`、`HeapFree`；外层 `while (!v10 && v20 < 100)` 限制最多约 100 轮，每轮 `InternetReadFile` 读入堆缓冲区并累加，失败则 `Sleep` 后重试。请求头/标志中含 `0x80000000`（`INTERNET_FLAG_RELOAD` 一类）。
- **4 字节滚动密钥解密**：下载完成后调用另一个解密函数，初始 `v4 = 1254685213 (0x4AC8FA1D)`，对每个字节 `i`：
  ```c
  c = buf[i];
  buf[i] = (BYTE)(v4 >> (8 * (i % 4))) ^ c;
  v4 = c | (v4 << 8);
  ```
  每解一个字节，就用该字节的**原始密文**左移 8 位并入滚动窗口，因此第 `i` 字节实际使用的密钥字节由种子和前面 1–3 个密文字节拼接而成；窗口循环 4 字节，属于自同步流式异或。解密必须使用原始密文更新 `v4`（不能用已解出的明文），实现时先保存 `c` 再覆盖。
- **链式效果**：URL 位移只保护“去哪里取”，滚动异或保护“取回来的内容”；两者都不依赖复杂密码学，分析者拿到静态字符串和函数即可离线还原 URL 与解密算法。文章发布时远程 `c.dat` 已失效，因此后续载荷内容未被还原。

## 触发条件

- 拿到银狐母体样本并完成前置 ShellCode 解密/环境检测，执行到远程配置获取阶段。
- 样本能访问外网（本例为阿里云 OSS `oss-4.oss-cn-hangzhou.aliyuncs.com`），且未被网络阻断。
- 分析侧能看到 URL 解密函数、WinInet 调用与下载后解密函数（IDA/Ghidra 静态或 x64dbg 动态）。
- 远程 URL 仍有效；文章发布时该 URL 已失效，只能还原算法与地址，无法取得后续加密数据。

## 利用步骤

1. 在样本字符串/栈上寻找 `seeadd://`、`zdd-`、`lwtjfynd`、`nzx` 等异常片段；对相关交叉引用定位解密函数与 `key=11`。
2. 用脚本对字母回退 11 位，得到 `https://oss-4.oss-cn-hangzhou.aliyuncs.com/c.dat`；在 x64dbg 中可等到解密后直接在栈上读取明文（文章截图在 `0x13C480` 处看到完整 URL）。
3. 定位 `InternetOpenA`、`InternetOpenUrlA`、`InternetReadFile` 调用点，确认下载缓冲区、最大轮数（约 100）与重试 `Sleep`。
4. 定位下载后的解密函数，确认初始 `0x4AC8FA1D` 与 `v4 = c | (v4 << 8)` 的滚动更新顺序。
5. 用 Python/C 复现滚动异或解密；若远程数据仍有效，抓包保存响应体后离线解密，再按文件头/PE 特征判断后续载荷类型。
6. 记录 IOC：加密 URL 形态、解密后 URL、OSS 域名、`c.dat` 路径、滚动密钥常量。

## PoC

URL 位移还原（Python，只读分析）：

```python
def shift_back(s, k=11):
    out = []
    for ch in s:
        if 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - ord('a') - k) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            out.append(chr((ord(ch) - ord('A') - k) % 26 + ord('A')))
        else:
            out.append(ch)
    return ''.join(out)

print(shift_back("seeadd://zdd-4.zdd-ny-slyrkszsf.lwtjfynd.nzx/n.ole"))
# https://oss-4.oss-cn-hangzhou.aliyuncs.com/c.dat
```

下载数据滚动异或还原（等价于原文反编译逻辑）：

```python
def rolling_xor(buf: bytearray) -> bytearray:
    v4 = 1254685213          # 0x4AC8FA1D
    for i in range(len(buf)):
        c = buf[i]           # 先保存原始密文字节
        buf[i] = ((v4 >> (8 * (i % 4))) & 0xFF) ^ c
        v4 = (c | (v4 << 8)) & 0xFFFFFFFF
    return buf
```

```text
原文动态证据（x64dbg）：
栈 0x13C480 处解密后的 URL：
https://oss-4.oss-cn-hangzhou.aliyuncs.com/c.dat
威胁情报：
SHA256 a657dcd661f87fbd68a50840efd64323f2aa1e816c700284aca59c82094ef418
URL    hxxps://oss-4.oss-cn-hangzhou.aliyuncs.com/c.dat
```

## 变体与关联

- 变体：位移密钥可改为其他 1–25 的值，或对大小写/数字使用不同字母表；也可在位移后再套 Base64/XOR。
- 变体：下载 API 可换成 `WinHttp`、`URLDownloadToFile`、`HttpClient`；下载后解密可换成 RC4/AES 或固定 key XOR。
- 关联：`[[pentest-c2-silverfox-two-stage-shellcode-loader]]`（同族加载器，下载 OSS `f.dat`）、`[[code-analysis-reverse-windows-silverfox-reversed-config-ipdates-info]]`（反转字符串 + 管道分隔配置，另一种银狐配置混淆）。
- 边界：文章发布时 `c.dat` 已失效，未取得下载后的真实密文，滚动异或只按反编译函数还原、未用真实样本验证输出；`InternetReadFile` 的具体缓冲区大小与 `GetData` 循环细节截图不完整。

## 检测与防御

- 检测：静态字符串出现 `seeadd://`、连续小写字母且整体不可读的类 URL 串；代码中存在 `(c - 'a' - k + 26) % 26 + 'a'` 形式的循环；导入 `InternetOpenUrlA`/`InternetReadFile` 后紧跟逐字节 XOR + 移位循环。
- 网络：监控对 `*.oss-cn-*.aliyuncs.com` 等对象存储的异常下载（尤其 `c.dat`、`f.dat` 等短路径），结合进程非浏览器、下载后无可执行落盘的行为。
- YARA/内存：匹配 `0x4AC8FA1D` 常量、`v4 = c | (v4 << 8)` 指令序列、字母回退循环与 `seeadd` 特征串。
- 加固：企业出口限制未分类对象存储下载；EDR 对“非浏览器进程 WinInet 下载 + 内存解密 + RWX 执行”组合告警；对银狐常用 OSS 域名做情报阻断。

---
id: defense-forensics-rdp-pfx-tls-decrypt-scancode-replay
title: RDP 流量解密与输入还原：导出 .pfx 私钥解 TLS，提取 fastpath scancode 还原键盘输入
type: scenario
domain: defense
path: defense/forensics
technique: rdp-pfx-tls-decrypt-scancode-replay
aliases:
- RDP 流量解密
- RDP 键盘输入还原
- fastpath scancode 解码
- 远程桌面证书私钥解密
- RDP 取证
tags:
- forensics
- traffic-analysis
- rdp
- tls
- scancode
- certificate
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:23:26+08:00'
  notes: 已对照原文与图14/15/16核对：SMB 导出 LOCAL_MACHINE Remote Desktop 0 WIN-*.pfx/.der、openssl pkcs12 -legacy 导证书/私钥、导入 Wireshark 解 TLS、rdp.fastpath.scancode.keycode 提取、PS/2 映射与 Shift/退格处理均与原文一致；图15 还原文本含漏键噪声（dart{5b3a641f-...}），卡片已注明需结合上下文修正。PoC 未本机复跑；原文未标注组件版本。
---

## 一句话结论

RDP 会话通常由 TLS 保护，抓包只能看到加密数据；如果能从被控主机/SMB 共享拿到远程桌面服务证书的 `.pfx`（含私钥）及其口令，就能在 Wireshark 中解密 TLS，再用 `rdp.fastpath.scancode.keycode` 提取键盘扫描码，按 PS/2 映射还原攻击者在远程桌面里输入的内容。

## 原理

- RDP 的标准安全层使用 TLS 加密整个连接（3389）；Wireshark 只能识别 RDP 协商阶段，后续 fastpath 输入/绘制数据不可见。
- 当 TLS 使用 RSA 密钥交换时，服务器证书私钥足以让 Wireshark 解密会话；`.pfx`（PKCS#12）同时包含证书与私钥，导入时需提供保护口令。若使用 ECDHE 等前向保密套件，仅私钥不够，需要 `SSLKEYLOGFILE` 或会话密钥。
- 解密后，RDP fastpath PDU 中会暴露 `rdp.fastpath.scancode.keycode`（按下/松开）以及 `rdp.fastpath.scancode.release`。键盘扫描码是 PS/2 Set 1 的原始键值，与字符的对应关系固定；结合 Shift/Ctrl 状态、退格、Tab、回车即可还原输入文本。
- 为什么可行：TLS 保护传输内容，但服务器私钥（或会话密钥）一旦泄露，历史 RDP 流量即可被离线解密；扫描码是客户端真实按键事件，不依赖屏幕截图或 OCR。
- 若攻击者通过剪贴板粘贴、鼠标点击软键盘或使用 Unicode 输入，可能不产生可还原的扫描码序列；此时需要结合剪贴板/PDU 其他字段分析。

## 触发条件

- 能获取包含 RDP 会话的 pcap（3389/TLS）。
- 能获取服务器 RDP 证书的 `.pfx` 及口令，或 TLS 会话密钥/`SSLKEYLOGFILE`。
- Wireshark 支持对应 TLS 套件；RDP 使用标准 TLS 安全层（非仅 CredSSP/NLA 的凭据阶段）。
- 攻击者在会话中通过键盘输入了敏感内容（命令、密码、flag 等）。

## 利用步骤

1. 在 SMB 流量/被控主机上找到远程桌面证书文件（常见 `LOCAL_MACHINE Remote Desktop 0 WIN-*.pfx` 与 `.der`），并取得 pfx 口令。
2. 导出证书与私钥（或直接把 pfx 导入 Wireshark 并输入口令）：
   ```bash
   openssl pkcs12 -legacy -in 1.pfx -clcerts -nokeys -out certificate.pem
   openssl pkcs12 -legacy -in 1.pfx -nocerts -nodes -out private.key
   ```
3. Wireshark → 编辑 → 首选项 → Protocols → TLS → RSA keys list，添加私钥（必要时附证书），输入 pfx 口令；若为 ECDHE，改用 `SSLKEYLOGFILE`/会话密钥。
4. 打开 RDP pcap，确认 TLS 解密成功，过滤 `rdp`；能看到 `Fast-Path PDU, Scancode` 等条目。
5. 用 tshark 提取扫描码：
   ```bash
   tshark -r 2-rdp.pcapng -Y "rdp.fastpath.scancode.keycode" \
     -T fields -e rdp.fastpath.scancode.keycode > keycode.txt
   ```
6. 用映射表解码：处理 Shift 切换、退格删除、Tab/回车；若未提取 release 字段，按连续重复项去重（按下/松开成对出现）。
7. 将还原文本与命令历史、时间线交叉验证；必要时调整过滤条件（源/目的 IP、端口）避免混入其他会话。

## PoC

```bash
# 1) 导出证书/私钥（pfx 口令按实际替换）
openssl pkcs12 -legacy -in 1.pfx -clcerts -nokeys -out certificate.pem
openssl pkcs12 -legacy -in 1.pfx -nocerts -nodes -out private.key

# 2) 提取扫描码
tshark -r 2-rdp.pcapng -Y "rdp.fastpath.scancode.keycode" \
  -T fields -e rdp.fastpath.scancode.keycode > keycode.txt
```

```python
import re
# PS/2 Set 1 常用键值；完整表按需补充
normal = {0x02:'1',0x03:'2',0x04:'3',0x05:'4',0x06:'5',0x07:'6',0x08:'7',
          0x09:'8',0x0A:'9',0x0B:'0',0x0C:'-',0x0D:'=',
          0x10:'q',0x11:'w',0x12:'e',0x13:'r',0x14:'t',0x15:'y',0x16:'u',
          0x17:'i',0x18:'o',0x19:'p',0x1A:'[',0x1B:']',
          0x1E:'a',0x1F:'s',0x20:'d',0x21:'f',0x22:'g',0x23:'h',0x24:'j',
          0x25:'k',0x26:'l',0x27:';',0x28:"'",0x29:'`',0x2B:'\\',
          0x2C:'z',0x2D:'x',0x2E:'c',0x2F:'v',0x30:'b',0x31:'n',0x32:'m',
          0x33:',',0x34:'.',0x35:'/',0x39:' '}
shift = {0x02:'!',0x03:'@',0x04:'#',0x05:'$',0x06:'%',0x07:'^',0x08:'&',
         0x09:'*',0x0A:'(',0x0B:')',0x0C:'_',0x0D:'+',
         0x10:'Q',0x11:'W',0x12:'E',0x13:'R',0x14:'T',0x15:'Y',0x16:'U',
         0x17:'I',0x18:'O',0x19:'P',0x1A:'{',0x1B:'}',
         0x1E:'A',0x1F:'S',0x20:'D',0x21:'F',0x22:'G',0x23:'H',0x24:'J',
         0x25:'K',0x26:'L',0x27:':',0x28:'"',0x29:'~',0x2B:'|',
         0x2C:'Z',0x2D:'X',0x2E:'C',0x2F:'V',0x30:'B',0x31:'N',0x32:'M',
         0x33:'<',0x34:'>',0x35:'?'}
special = {0x01:'[ESC]',0x0E:'[BACKSPACE]',0x0F:'[TAB]',0x1C:'\n'}
SHIFT_KEYS = {0x2A,0x36}

codes = [int(x,16) for x in re.findall(r"0x[0-9a-fA-F]+", open("keycode.txt").read())]
dedup = []
for c in codes:
    if not dedup or dedup[-1] != c:
        dedup.append(c)

out, sh = [], False
for c in dedup:
    if c in SHIFT_KEYS:
        sh = not sh; continue
    if c == 0x0E:
        if out: out.pop()
        continue
    if c in special:
        out.append(special[c]); continue
    out.append((shift if sh else normal).get(c, f"[0x{c:02x}]"))
print("".join(out))
```

说明：PoC 为原文流程的结构化精简，未在本机执行；原文输出的 flag 文本因漏键/重复键有噪声，需结合上下文修正。仅用于授权取证。

## 变体与关联

- 变体（TLS 套件）：RSA 密钥交换可直接用私钥；ECDHE 需要 `SSLKEYLOGFILE`、会话密钥或内存中的 TLS 主密钥。
- 变体（输入通道）：剪贴板、鼠标、Unicode 输入可能不产生扫描码；需结合 RDP 剪贴板 PDU、绘制命令或主机侧日志。
- 变体（证书来源）：除了 SMB 导出，也可从被控主机注册表/文件系统、备份、内存镜像获取 `.pfx`；口令可能来自 Mimikatz/配置。
- 关联：[[defense-forensics-smb3-session-key-wireshark-decrypt]]（前置：解密 SMB3 后才能导出 pfx）；[[defense-forensics-winrm-ntlm-traffic-decrypt-soap-command]]（同一横向链的 WinRM 阶段）；[[pentest-ad-mimikatz-dpapi-masterkey-saved-rdp-credential]]（RDP 凭据的另一获取方式）。
- 边界：RDP 使用 CredSSP/NLA 且无 TLS 私钥、ECDHE 且无会话密钥、输入以粘贴/鼠标为主、或证书口令未知时，本方法不成立或只能还原部分输入。

## 检测与防御

- 检测：3389 端口出现异常来源/时间登录；RDP 会话中出现大量 Fast-Path Scancode 与敏感命令；同一主机在短时间内被多个账号/来源 RDP 登录。
- 防御：限制 RDP 来源 IP，禁止普通内网主机直连敏感服务器；启用 NLA、网络级认证与 MFA；及时更新 RDP 与 TLS 配置。
- 加固：保护远程桌面证书私钥与 pfx 口令，避免存放在可被 SMB 读取的共享；使用 ECDHE 等前向保密套件并保护会话密钥；监控证书导出与异常文件访问。
- 取证：保存 pcap、私钥与解密结果作为证据；对还原输入与主机日志（Security 4624/4648、PowerShell 日志）交叉验证。

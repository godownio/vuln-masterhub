---
id: defense-forensics-njrat-c2-traffic-base64-decode
title: NjRAT/Bladabindi C2 流量识别与解码：明文上线包、Base64 受害者信息、act/kl/pas 命令与 CAP JPEG 桌面帧
type: scenario
domain: defense
path: defense/forensics
technique: njrat-c2-traffic-frame-decode
tags:
- forensics
- traffic-analysis
- windows
- c2
- njrat
- bladabindi
- base64
- rat
- keylogger
- incident-response
cve: []
severity: high
confidence: high
affected_versions: NjRAT 0.7d Green Edition（原文样本；字段分隔符与命令集随 Builder/改版可能变化）
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V191
  verified_at: '2026-11-06T23:10:35+08:00'
  notes: 已对照原文与53张图核对：TCP三次握手131:60685→129:1234、首包SGFJ(Base64机器ID)+|'|'|明文主机名/用户名/日期/Win10ProSP0 x64/No/im523、第二包整包Base64解码、kl响应Base64、pas命令+dl.dropbox.com、CAP|'|'|+JPEG帧均一致。核对中发现原文称第二包字段为“受害者IP和端口”有误，实际解码为192.168.111.129:1234即Builder配置的C2 Host:Port（受害机为131，端口60685），已修正沙箱卡与知识库卡并保留原文误标说明；Victim Name字段亦已注明为Builder设置值
url: /docs/defense/forensics/defense-forensics-njrat-c2-traffic-base64-decode/
draft: false
kb_aliases:
- NjRAT 流量分析
- Bladabindi 协议
- NjRAT C2 解码
- act kl pas 命令
- CAP JPEG 桌面帧
- 远程桌面缩略图流量
- NjRAT 上线包
---

## 一句话结论

NjRAT/Bladabindi 使用原始 TCP 与 C2 通信，以 `|'|'|` 分隔字段、仅对特定字段做 Base64：受害端首包是“Base64 机器 ID + 明文主机名/用户名/日期/系统/架构/摄像头/版本/活动窗口”，第二包整体 Base64 承载 Builder 设置的 Victim Name、C2 Host:Port（原文误称“受害者 IP 和端口”；文中解码值为 `192.168.111.129:1234`，与 Builder 的 Host/Port 一致）、可执行文件位置与文件名和 Builder 选项；C2 下发 `act`/`kl`/`pas` 等短命令，键盘日志与密码文件 Base64 回传，远程桌面则以 `CAP|'|'|` + JPEG 逐帧传输。按这些定界符和命令即可从 PCAP 还原上线主机与远控操作。

## 原理

- **协议分层**：NjRAT 没有自定义二进制帧头，而是把字段拼成可打印字符串，用固定分隔符 `|'|'|`（管道、单引号、管道、单引号、管道）连接；字符串中的部分敏感字段（机器 ID、第二包全部字段、键盘日志、密码文件）再做 Base64。Base64 只是编码不是加密，抓包即可离线还原。
- **首包（上线信息）**：受害端主动连接 C2 后发送的第一条消息，开头是指定机器 ID 的 Base64 串，随后用分隔符拼接主机名、用户名、文件最后写入日期、操作系统名、系统架构、是否有摄像头、NjRAT 版本号、当前活动窗口标题。除机器 ID 外均为明文，可用于快速确认感染主机与样本版本。
- **第二包（受害者详情）**：整包为 Base64，解码后仍以分隔符分隔：Builder 设置的 Victim Name、C2 Host:Port（原文误称“受害者 IP 与端口”；截图解码为 `192.168.111.129:1234`，即 Builder 配置的 C2 地址，不是受害机 `192.168.111.131` 的地址）、可执行文件所在目录/位置、可执行文件名，以及与 Builder 勾选项对应的一串 True/False（隐藏、注册表自启、启动目录、关键进程、USB 传播、杀进程等）。这一串布尔值等于远程还原了 Builder 配置。
- **命令通道**：C2 向受害端发送短命令，例如 `act` 请求活动窗口、`kl` 启动/读取键盘记录、`pas` 执行密码收集。命令本身很短，常与数据包长度一起暴露在 TCP 流中；响应按命令名 + 分隔符 + Base64 数据回传。
- **键盘记录**：C2 下发 `kl` 后，被控端把击键日志 Base64 编码回传；日志通常包含窗口标题切换与按键文本，可直接还原用户输入（账号、聊天、搜索词）。
- **密码收集 `pas`**：被控端收到 `pas` 后访问 Dropbox 上的 `Pass.exe`，运行后扫描本机保存的密码并写入 `temp.txt`，再以 `pas|'|'|<Base64(temp.txt)>` 回传。流量侧表现为 C2 会话内出现 `pas` 短包，同时伴随对 `dl.dropbox.com` 的 DNS/HTTPS 请求。
- **远程桌面**：被控端把桌面截图编码为 JPEG，按 `CAP|'|'|` + JPEG 数据逐帧发送；截图分辨率可很小（示例为 35x23 缩略图），但连续帧仍可还原屏幕内容。由于是原始 TCP 上的连续 JPEG 流，按 `CAP|'|'|` 切帧、从下一个 JPEG SOI（`FF D8`）到 EOI（`FF D9`）即可提取图片。
- **为什么容易漏检**：端口可配置、无 TLS、字段是明文/Base64 混合，传统基于固定端口的规则容易漏；反之，分隔符与 `CAP|'|'|` 是稳定度较高的家族指纹。

## 触发条件

- 已捕获受害主机与 NjRAT C2 之间的 TCP 流量（全流量镜像、主机抓包或沙箱 PCAP）。
- 流量未被 TLS 封装；NjRAT 默认明文 TCP，若改版启用 TLS 则需先解密。
- 分析者知道或能猜出 C2 端口；不知道时可从异常长连接、非标准高端口、`|'|'|` 字符串或 JPEG 魔数入手。
- 需要完整第二包/键盘日志时，PCAP 必须包含会话建立后的双向数据，而不只是握手。

## 利用步骤

1. **定位会话**：在 Wireshark 中过滤 `tcp.port == <C2端口>` 或按受害 IP 过滤，找三次握手后受害端发出的首个 PSH 包。
2. **拆首包**：把 TCP 载荷按 `|'|'|` 分割；第一段做 Base64 解码得到机器 ID；其余段直接读主机名、用户名、日期、OS、架构、摄像头、版本、活动窗口。
3. **解第二包**：取受害端后续数据包，对整段做 Base64 解码，再按 `|'|'|` 分割，读出 Victim Name、C2 Host:Port、路径、文件名和 True/False 配置串。
4. **识别命令**：在 C2→受害端方向查找长度很短的 ASCII 包（`act`、`kl`、`pas` 等）；在受害端→C2 方向找同名前缀 + Base64 的响应。
5. **还原键盘记录**：对 `kl` 响应中分隔符后的 Base64 解码，得到击键文本与窗口标题序列。
6. **提取桌面帧**：对含 `CAP|'|'|` 的载荷，从分隔符后找 `FF D8 ... FF D9` 提取 JPEG；跨 TCP 段的帧需先重组流再切分。
7. **关联主机侧**：结合进程树与文件痕迹（`%TEMP%` 副本、启动目录隐藏 EXE、`HKCU\di`、随机名 Run 值）确认同一受害主机。

## PoC

离线解析脚本（仅处理已捕获的 PCAP，不连接 C2）：

```python
import base64, re

SEP = b"|'|'|"

def split_fields(payload: bytes):
    return payload.split(SEP)

def try_b64(data: bytes):
    try:
        return base64.b64decode(data, validate=True)
    except Exception:
        return data

# 首包：第一段是 Base64 机器 ID，其余为明文字段
first = b"SGFJ|'|'|DESKTOP-EXAMPLE|'|'|user|'|'|25-11-19|'|'|Win 10 ProSP0 x64|'|'|No|'|'|im523|'|'|Notepad"
parts = split_fields(first)
machine_id = try_b64(parts[0]).decode(errors="replace")
print("machine_id:", machine_id)
print("host/user/os:", [p.decode(errors="replace") for p in parts[1:]])

# 第二包：整包 Base64，解码后仍是 |'|'| 分隔
second_b64 = b"SGFja2VkfCd8J3wxOTIuMTY4LjEuMTA6MTIzNHwnfCd8RGVza3RvcHwnfCd8U2VydmVyLmV4ZXwnfCd8RmFsc2V8J3wnfFRydWV8J3wnfFRydWV8J3wnfFRydWU="
decoded = try_b64(second_b64)
print([p.decode(errors="replace") for p in split_fields(decoded)])

# CAP 桌面帧：分隔符后提取 JPEG SOI..EOI
def extract_jpegs(stream: bytes):
    out = []
    for chunk in stream.split(b"CAP|'|'|")[1:]:
        start = chunk.find(b"\xff\xd8")
        end = chunk.find(b"\xff\xd9", start + 2)
        if start >= 0 and end > start:
            out.append(chunk[start:end + 2])
    return out
```

Wireshark 侧可用 `tcp.stream eq <n>` 跟踪流，再 `File → Export Objects → Raw` 或 tshark 提取 `tcp.payload`；对 Base64 字段用 CyberChef 的 From Base64 一步还原。

## 变体与关联

- **分隔符/编码变体**：改版可替换 `|'|'|`、改用其他 Base64 变体或先压缩再 Base64；应以样本 `OK.ENB/OK.DEB` 的实际实现为准。
- **端口与 TLS**：端口由 Builder 指定；部分改版加入 TLS/自定义异或，需要先解密或 hook 发送函数。
- **桌面帧变体**：`CAP|'|'|` 后可能是 JPEG 也可能是原始位图/PNG；连续帧可带缩放参数，需按实际 SOI/EOI 提取。
- **密码收集变体**：`pas` 的下载地址可换成其他网盘/HTTP 地址，回传文件名也可变化。
- 关联：[[defense-forensics-winos4-c2-frame-xor-decrypt]]（二进制长度帧 + 滚动 XOR 的另一种远控协议）、[[defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt]]（长度+nonce+GCM 帧）、[[code-analysis-reverse-windows-njrat-vbnet-dnspy-install-c2-analysis]]（样本静态侧的方法与字段来源）、[[pentest-persistence-njrat-install-firewall-run-startup-usb]]（主机侧安装行为）。

## 检测与防御

- **网络检测**：在 IDS/NDR 中匹配 `|'|'|`、`CAP|'|'|` 与短命令 `act`/`kl`/`pas` 的组合；对原始 TCP 非标准端口长连接、单包内出现可打印分隔符与 Base64 混合内容告警；监控 `dl.dropbox.com`/`dropbox.com` 上 `Pass.exe` 的下载与随后同名 C2 会话。
- **主机检测**：结合 `%TEMP%` 自复制、启动目录隐藏 EXE、`HKCU\di`、随机名 Run 值、`netsh firewall add allowedprogram`、`taskkill /F /IM` 等 NjRAT 安装痕迹；键盘记录与远程桌面通常不落盘，需以网络行为为主。
- **取证要点**：优先保全完整双向 PCAP 与进程内存；按流重组后再切 `CAP` 帧，避免跨段丢帧；把首包机器 ID 与主机名/IP 建立映射，便于多主机批量识别。
- **防御**：限制工作站对陌生高端口的出站连接；对 Office 宏/脚本宿主拉起的子进程做父子链检测；禁用不必要的可移动介质自动执行；发现 NjRAT 后隔离主机、重置在该机登录过的账号口令，并检查 Dropbox 密码收集与键盘记录造成的信息泄露范围。

---
id: ctf-web-awd-shared-secret-batch-replay
title: AWD 同构靶机共享密钥批量打法：一份 Shiro rememberMe Cookie（或固定口令）打全场收 flag
type: scenario
domain: ctf
path: ctf/web
technique: awd-shared-secret-batch-replay
aliases:
- AWD 批量打靶
- 同构靶机批量利用
- 固定密钥批量重放
- rememberMe Cookie 批量
- 全场同密码
- urls.txt 批量请求
tags:
- ctf
- awd
- batch
- shiro
- rememberme
- fixed-key
- replay
- java
- automation
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V443
  verified_at: '2026-11-09T23:02:56+08:00'
  notes: '对照原文 13 图与正文：同构靶机共享强口令/固定密钥的批量重放主线（SSH 拖源码取 ShiroConfig 固定 cipherKey QZ1ysgMYhG7/CzIJlVpR1g==、CC/CB 依赖、SummerSec 工具生成 rememberMe Cookie、Wireshark 抓 127.0.0.1:8080 确认、urls.txt 批量请求、响应 $$$ 包裹 Base64 解码）均与原文一致；靶机二 forget.jsp cmd 命令执行、Filter 内存马与靶机三 Shiro 固定 key 的细节与图片一致。小问题（不影响卡可用性）：PoC 中 Authorization: Basic d2hvYW1p 在原文是 whoami 的 base64 标记而非"命令输出对应的 Basic 凭据"，注释表述不准确；原理中"批量执行 cat /flag*"是结合靶机一 payload 的合理外推，原文靶机二只演示 whoami 与内存马批量思路。worker 跳过判断核实成立：靶机二 Filter 动态注册已由既有 filterConfigs 直插/ApplicationFilterConfig 卡覆盖，靶机三固定 cipherKey 反序列化由 Shiro-550 硬编码密钥卡覆盖；靶机一作者未独立打通、仅复用他人木马发一条请求，不构成完整链。dedup top 候选均为 Shiro 利用手法的单点卡，非同一条链。原文无版本，--clear。未本机复跑。'
---

## 一句话结论

AWD 各队靶机通常是同一镜像，比赛方发放的强口令或应用内固定密钥往往各队相同；只要漏洞利用载荷是"无状态"的（如 Shiro 用固定 AES key 加密的 `rememberMe` Cookie），在一台靶机上验证成功后，同一份 Cookie 可直接重放到所有队伍 IP，用脚本遍历目标列表即可批量收 flag；固定口令、固定 JWT 密钥同理。

## 原理

- **同构环境**：AWD 通常用同一套镜像/附件部署到所有队伍，系统账号、应用管理员口令、加密密钥都可能一致；即使不是弱口令，若"强口令所有人相同"，泄露一次即全场可用。
- **无状态载荷**：Shiro-550 的 `rememberMe=base64(IV+ciphertext)` 由服务端固定 `cipherKey` 加密，与服务端会话、目标 IP、时间都无关；只要目标密钥相同，同一 Cookie 在任意靶机都能被解密并反序列化执行同一命令。这与需要先登录拿 session 的漏洞不同，天然适合批量重放。
- **获取密钥与验证**：从自己靶机的源码/配置（本题通过 SSH 登录靶机拖源码）或附件中找到 Shiro 配置里的固定 `cipherKey` 与 CC/CB gadget 依赖；用 Shiro 利用工具生成命令 payload 与 Cookie，先打自己的靶机验证回显/外带，再批量。
- **批量执行**：把全部目标 IP 写入 `urls.txt`，脚本对每个 `http://ip` 带上同一 Cookie（以及必要的 Basic/自定义头）发请求；响应按约定解码（本题响应为 `$$$` 包裹的 Base64 命令输出），提取 flag。
- **另一类批量面**：本题靶机二存在 `forget.jsp` 命令执行且带回显，可直接用同一请求模板批量执行 `cat /flag*`；进一步可上传 Tomcat Filter 内存马（`filter.jsp` 动态注册恶意 Filter，`cmd` 参数触发）把一次性命令执行变成稳定后门，再批量控制。
- **成立前提**：同构、同密钥/同口令、目标可从攻击网络访问、漏洞无每实例独有状态；任一不满足（如每队随机密钥）批量即失效。

## 触发条件

- AWD/靶场中有多台同构目标，且可从比赛网络批量访问（HTTP/SSH 等）。
- 已在任一目标取得源码/配置或已知固定密钥、固定口令、固定 JWT secret。
- 存在无状态可重放的利用载荷（Shiro rememberMe Cookie、固定 Basic 凭据、固定签名 token 等）。
- 目标未对同一来源的批量请求做频率限制（或控制在规则允许范围内）。

## 利用步骤

1. 通过 SSH/附件/源码泄露拿到自己靶机的应用配置，定位固定密钥或默认口令（本题为 Shiro `cipherKey`，依赖含 CC/CB）。
2. 用工具生成一次 payload/Cookie，先打自己的靶机验证命令执行与回显方式（本题用 Wireshark 确认 rememberMe 请求与响应）。
3. 收集所有队伍靶机 IP 写入 `urls.txt`。
4. 编写脚本：对每个 IP 发送同一 Cookie/凭据（必要时附带 Basic 认证头），按响应格式解码（本题 Base64、去 `$$$`），打印成功的 IP 与 flag。
5. 对命令执行型漏洞可替换命令批量读 flag；需要稳定控制时先批量上传内存马（如 Tomcat Filter 型），再走内存马通道。
6. 控制并发与超时，记录失败目标，避免把服务打挂或触发封禁。

## PoC

```python
import base64
import requests

headers = {
    # 用固定密钥生成一次即可，全场复用
    "Cookie": "rememberMe=<预生成的 payload>",
    "Authorization": "Basic d2hvYW1p",          # 可选：命令输出对应的 Basic 凭据
    "User-Agent": "Mozilla/5.0",
    "Accept-Encoding": "gzip, deflate",
}

for ip in open("urls.txt"):
    ip = ip.strip()
    if not ip:
        continue
    try:
        r = requests.get(f"http://{ip}", headers=headers, timeout=5)
        if r.status_code == 200:
            out = base64.b64decode(r.text.strip("$$$")).decode("utf-8", "ignore")
            print(f"[+] {ip}: {out}")
        else:
            print(f"[-] {ip}: HTTP {r.status_code}")
    except Exception as e:
        print(f"[!] {ip}: {e}")
```

说明：Cookie 需先用目标相同的 `cipherKey` 生成；响应解码格式按实际漏洞调整。

## 变体与关联

- 变体：固定管理员口令 → 批量登录后台；固定 JWT HS256 secret → 本地签发 admin token 打全场；固定数据库口令/云密钥同理。
- 变体：命令执行漏洞可先批量写内存马（Tomcat Filter/Servlet、哥斯拉等），再统一走内存马通道；本题靶机二即用 `forget.jsp` 命令执行投放 Filter 内存马。
- 关联：[[web-java-framework-shiro-550-hardcoded-key-deserialization]]（rememberMe 固定密钥原理）；[[web-java-component-tomcat-dynamic-filter-memshell]]（命令执行后投放 Filter 内存马）；[[ctf-pwn-awd-batch-scan-concurrent-exp-runner]]（AWD 批量编排的二进制版）；[[ctf-web-go-server-local-replay-admin-jwt]]（同构建/同密钥导致本地 token 打远端的另一案例）。

## 检测与防御

- 防守方（AWD）：为每队生成唯一密钥/口令，比赛开始前轮换 `cipherKey`、JWT secret、管理员口令；删除 CC/CB 等不必要 gadget 依赖；修复命令执行点；对同源高频请求限速；移除或禁用 rememberMe。
- 出题方：镜像内不写死共享密钥；赛前检查所有队伍实例的密钥与口令唯一性；对批量重放行为做监控。
- 局限：批量打法只对同构共享密钥有效；每队随机化后需逐目标单独获取密钥，成本大幅上升。

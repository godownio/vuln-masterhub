---
id: web-generic-file-inclusion-windows-sam-ntlm-crack
title: 文件包含读取 Windows SAM 备份并破解 NTLM 哈希获取明文口令
type: scenario
domain: web
path: web/generic/file-inclusion
technique: lfi-windows-sam-hash
aliases:
- 文件包含读 SAM
- Windows SAM 备份
- C:\WINDOWS\repair\SAM
- LFI NTLM 哈希
- 包含密码文件
tags:
- file-inclusion
- lfi
- windows
- sam
- ntlm
- credential-access
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-E
  verified_at: '2026-11-04T19:20:54+08:00'
  notes: 已对照原文核对：LFI 包含 C:\WINDOWS\repair\SAM、响应哈希行、john -w=rockyou.txt 破解与原文一致；需注意原文响应行为 NetNTLMv2 challenge-response 格式，与 SAM hive 内 NT hash 不等价，包含 SAM 能否直接得到该行需复现确认（卡内 confidence=medium）；PoC 未在本机执行。
---

## 一句话结论

Windows Web 应用存在本地文件包含时，包含 `C:\WINDOWS\repair\SAM` 这类 SAM 备份文件可读出本地账户的 NTLM 哈希，离线字典破解后得到明文口令并用于横向。

## 原理

- 文件包含漏洞把用户可控参数当作文件路径读取或执行。攻击者可以指定 Windows 绝对路径，让 Web 进程读取服务器本地文件。
- 实时 SAM（`C:\Windows\System32\config\SAM`）被系统锁定，Web 进程通常无法直接读取；`C:\WINDOWS\repair\SAM` 是系统修复/安装阶段保留的备份，权限往往更宽松，是更现实的读取目标。
- SAM 中保存本地账户的 NTLM 哈希。攻击者拿到哈希后可离线用 john/hashcat 加字典破解；若口令较弱或与其他系统复用，即可恢复明文。
- 案例中文件包含读取 `C:\WINDOWS\repair\SAM` 后，响应直接给出了 `administrator::PYH-PC:...` 形式的 NTLMv2 行；用 `john -w=rockyou.txt` 破解出管理员明文口令，随后用于远程登录。
- 该路径的成立依赖 Web 进程对备份文件的读取权限，以及目标本地管理员口令可被字典命中；两者缺一不可。

## 触发条件

- Web 应用存在本地文件包含/任意文件读取入口；
- Web 进程账户有权读取 `C:\WINDOWS\repair\SAM` 或其他 SAM 备份；
- 目标为 Windows，本地账户使用可被字典破解的口令；
- 攻击者能离线运行 hashcat/john，或目标口令与其他系统复用。

## 利用步骤

1. 找到文件包含参数（`file`、`page`、`path`、`template` 等），用 `C:\Windows\win.ini`、`boot.ini` 验证绝对路径读取。
2. 尝试包含 `C:\WINDOWS\repair\SAM`、`C:\Windows\repair\SYSTEM` 等备份文件。
3. 从响应中提取 `user::host:LM:NT:...` 格式的哈希行，保存为 `hash.txt`。
4. 用 john/hashcat 加字典破解：`john -w=rockyou.txt hash.txt`。
5. 用恢复的明文口令尝试 RDP/SMB/其他服务登录；若失败，考虑口令变体与复用。
6. 若无法直接读取备份，可评估日志包含、临时文件包含或 `php://filter` 读二进制等其他 LFI 利用方式。

## PoC

```http
GET /index.php?file=C:\WINDOWS\repair\SAM HTTP/1.1
Host: target
```

```text
# 响应中可能出现（示意）
administrator::HOST:LMHASH:NTHASH:...
```

```bash
# 离线破解（仅在授权环境使用）
john -w=rockyou.txt hash.txt
```

## 变体与关联

- 变体：读取 `C:\Windows\System32\config\SAM` + `SYSTEM`（通常被锁）、`C:\Windows\repair\SYSTEM`、`NTDS.dit`（域控）、`unattend.xml`、`web.config`、IIS `applicationHost.config`；`php://filter/convert.base64-encode` 读二进制；LFI 日志包含/临时文件包含转 RCE。
- 关联：[[web-php-file-inclusion-thinkphp-view-template]]（PHP 文件包含 RCE）；[[pentest-initial-access-password-semantic-mutation-reuse]]（破解后的口令复用）。
- 影响边界：案例最终破解出管理员明文口令并远程登录，构成主机控制；若 SAM 备份不可读或口令强度足够，危害降级为文件读取。

## 检测与防御

- 检测：请求参数中出现 `SAM`、`SYSTEM`、`win.ini`、`boot.ini`、`\Windows\` 等路径；Web 进程读取系统配置/备份目录；异常 200 响应中包含哈希格式；后续 RDP/SMB 登录失败与成功。
- 修复：修复文件包含漏洞，对包含路径使用白名单/固定映射，禁止绝对路径与目录穿越。
- 缓解：Web 进程降权，禁止读取 SAM/SYSTEM 备份；移除或收紧 `C:\Windows\repair` 权限；启用 LAPS 与强口令；监控敏感文件访问。

---
id: defense-incident-response-hidden-dotfile-base64-decode
title: Web 根隐藏 dotfile 排查：.tools.sh 内 Base64 数据解码取证
type: scenario
domain: defense
path: defense/incident-response
technique: hidden-dotfile-base64-decode
aliases:
- 隐藏 dotfile 排查
- .tools.sh
- find -name '.*'
- Base64 隐藏数据解码
- Web 根隐藏脚本取证
tags:
- incident-response
- hidden-file
- dotfile
- base64
- linux
- web-root
- forensics
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V314
  verified_at: '2026-11-08T13:52:56+08:00'
  notes: 拆分后复核：对照图13 .tools.sh（91B/-rwxrwxrwx）与图14 Base64解码结果核对，单一原子、独立触发条件与PoC成立
---

## 一句话结论

Web 根目录中以 `.` 开头的文件不会被常规 `ls`/目录列表展示，也常被扫描器跳过；完整取得 Web 目录后枚举 dotfile，对内容里形似 `echo <base64> > /dev/null` 的长串做 Base64 解码，即可还原出被隐藏的数据。本题 `/www/html/.tools.sh` 中的 Base64 串解码得到 `flag{f665fc9b-965a-43ed-b235-e32982cc280f}`。

## 原理

- **dotfile 默认不可见**：`ls`、文件管理器与部分 Web 扫描器默认不展示或跳过以 `.` 开头的文件，攻击者/出题人常借此藏脚本、凭据或标记数据。
- **`echo <base64> > /dev/null` 只是障眼法**：输出被丢弃，但 Base64 字符串仍留在脚本文件里；读取文件即可提取并解码。
- **编码可叠加**：若字符串先做过 URL 编码，直接 Base64 解码会失败，需要先 URL Decode 再 From Base64（CyberChef 的 URL Decode → From Base64 配方即可）。
- **可疑信号**：`.tools.sh` 仅 91 字节、权限 `-rwxrwxrwx`、mtime 明显新于同目录业务文件；同目录还有 `hazel.php` 等被扫描器标记的文件，说明该目录需要整体复核。

## 触发条件

- 能取得 Web 根目录的完整拷贝，或具备主机文件系统访问权限。
- 目录中存在以点开头的文件（`.tools.sh`、`.env`、`.user.ini`、`.htaccess`、`.git/` 等）。
- 需要确认 Web 目录中是否藏有编码数据、凭据或后门脚本。

## 利用步骤

1. **固定证据**：打包 Web 目录并计算哈希，记录获取时间与主机；不要先删除或修改 dotfile。
2. **枚举隐藏文件**：用 `find -name '.*'` 列出 dotfile，记录权限、mtime、大小与所属目录。
3. **查看内容**：重点看短小的可执行脚本、看似无害的 `echo`/注释与超长字符串。
4. **提取并解码**：抓取长度 ≥16 的 Base64 字符集片段；若失败，检查是否先做了 URL 编码或反转等前置变换。
5. **关联与处置**：将解码结果与文件列表、访问日志、扫描器结果交叉；若为凭据或真实后门数据，隔离样本、轮换凭据并清理。

## PoC

```bash
# 1) 枚举 Web 根目录下的隐藏文件（权限/时间/大小/路径）
find /www/html -type f -name '.*' -printf '%M %TY-%Tm-%Td %TH:%TM %s %p\n'

# 2) 查看 .tools.sh 内容（形如 echo <base64> > /dev/null）
cat /www/html/.tools.sh

# 3) 提取其中长度 >=16 的 Base64 串并解码
grep -oE '[A-Za-z0-9+/]{16,}={0,2}' /www/html/.tools.sh | while read -r b; do
  printf '%s -> ' "$b"
  printf '%s' "$b" | base64 -d 2>/dev/null; echo
done
# flag{f665fc9b-965a-43ed-b235-e32982cc280f}
```

若输入是 URL 编码后的 Base64，先解码 URL 再做 Base64：

```bash
printf '%s' "$RAW" | python3 -c 'import sys,urllib.parse;sys.stdout.write(urllib.parse.unquote(sys.stdin.read()))' | base64 -d
```

## 变体与关联

- **dotfile 类型变体**：`.env` 泄露数据库/API 凭据；`.git/` 泄露源码与历史；`.user.ini` 的 `auto_prepend_file` 可劫持 PHP 入口；`.htaccess` 可注册 handler；另有 `.idea/`、`.index.php.swp`、`.bak` 等隐藏备份。
- **编码变体**：hex、base32、反转 + Base64、URL 编码 + Base64 等叠加，解开一层后要继续观察输出是否仍是编码。
- 关联：[[defense-incident-response-dshield-level-webshell-triage]]（同一 Web 根目录的 D盾分级扫描；其级别 5 命中文件 `.func.php` 也是隐藏点文件）、[[defense-forensics-python-malware-reversed-base64-url-config]]（反转 + Base64 + URL 编码的配置串还原）。
- **注意**：隐藏文件枚举与 webshell 扫描互补——扫描器能命中 `.func.php` 之类的点文件，但不一定检查 `.tools.sh` 这类非 PHP 脚本；反之亦然。

## 检测与防御

- **检测**：文件完整性监控对 Web 根目录 dotfile 的新增/修改告警；用 auditd 监控 Web 目录的 `open`/`creat`/`rename`；定期 `find -name '.*'` 审计。
- **防御**：Web 服务器拒绝访问点文件（Nginx `location ~ /\. { deny all; }`，Apache `<FilesMatch "^\."> Require all denied </FilesMatch>`）；上传目录禁止执行；敏感配置不放在 Web 根目录。
- **响应**：先保留 dotfile 原样与哈希，再排查其是否被 cron/systemd/启动脚本引用；确认泄露的凭据立即轮换。

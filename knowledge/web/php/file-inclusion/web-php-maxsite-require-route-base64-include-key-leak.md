---
id: web-php-maxsite-require-route-base64-include-key-leak
title: MaxSite CMS require-maxsite 路由：Base64 路径包含泄露更新密钥与源码
type: scenario
domain: web
path: web/php/file-inclusion
technique: maxsite-require-base64-include-key-leak
aliases:
- require-maxsite
- MaxSite CMS
- base64 include
- edge_key_release_2026
- update-maxsite
- maintenance trace
tags:
- php
- maxsite
- file-inclusion
- base64
- source-leak
- update-key
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:11:32+08:00'
  notes: '已对照原文截图核对并修正：首页 trace 的真实 Base64 段为 Y3RmL3VwZGF0ZS1rZXktcmVxdWlyZS1tYXhzaXRlLnBocA==（解出 ctf/update-key-require-maxsite.php，页面输出 Key: edge_key_release_2026），原卡误写为 ctf/edge_key_release_2026.php 且 PoC Base64 不匹配，已按截图改正；其余路由/include 机制与原文一致；未实际运行 PoC。'
---

## 一句话结论

MaxSite CMS 首页的 `maintenance trace` 链接是 `/require-maxsite/<base64>`；该路由把 Base64 解码成 `base_dir` 下的路径并包含 `*-require-maxsite.php` 文件，受控 include 文件输出更新密钥 `edge_key_release_2026`，用密钥访问 `/update-maxsite/?edge_key_release_2026` 即可下载 `master.zip`，从源码/配置中拿到低权限账号。

## 原理

- **路由**：CodeIgniter 的 `maxsite.php` 控制器 `_remap` 把 URL 第一段 `require-maxsite` 映射到 `_view_i('require-maxsite', 'require-maxsite')`，加载 `application/views/require-maxsite.php` 视图。
- **Base64 路径**：视图取 `uri_segment[2]`，`base64_decode` 后拼到 `$MSO->config['base_dir']`，并验证：文件存在、文件名包含 `-require-maxsite.php` 后缀、路径在 `base_dir` 下（防目录遍历）。满足后 `include` 该文件。
- **受控 include 的风险**：后缀白名单只限制“文件名包含 `-require-maxsite.php`”，不限制文件内容；`base_dir` 下任何符合后缀的文件都会在 CMS 全局上下文（`$MSO`、`is_login()` 等已初始化）中执行。若某个此类文件输出密钥/配置，攻击者可直接读取。
- **本题链**：首页的维护 trace 指向 `ctf/update-key-require-maxsite.php`（原文截图 URL 中 Base64 段 `Y3RmL3VwZGF0ZS1rZXktcmVxdWlyZS1tYXhzaXRlLnBocA==` 解码结果）；访问后页面输出 `Key: edge_key_release_2026` 和 `Use Key to Download! /update-maxsite/master.zip`。用该 key 访问 `/update-maxsite/?edge_key_release_2026`，更新器解压 `master.zip` 到 webroot，源码/配置中可找到低权限账号 `user / minsite-user-2025`。
- **为什么不能直接访问插件 PHP**：`uploads-require-maxsite.php` 等文件开头有 `if (!defined('BASEPATH')) exit(...)`，直接访问会被拒绝；必须通过 `require-maxsite` 路由在框架上下文里 include。

## 触发条件

- MaxSite CMS 启用 `require-maxsite` 路由（`application/views/require-maxsite.php` 存在）。
- `base_dir` 下存在可输出的 `*-require-maxsite.php` 文件（更新密钥、配置、调试信息）。
- 攻击者能访问站点并解码首页/页面中的 Base64 链接。
- `/update-maxsite/` 更新端点可达，且 key 校验只在客户端/弱校验。

## 利用步骤

1. 在首页/页面中找 `require-maxsite/<base64>` 形式的链接（如 `maintenance trace`）。
2. Base64 解码第二段，得到 `base_dir` 下的相对路径（本题 `ctf/update-key-require-maxsite.php`）。
3. 访问 `http://target/require-maxsite/<原base64>`，读取页面输出的更新密钥。
4. 用密钥访问 `http://target/update-maxsite/?<key>`，触发更新器下载/解压 `master.zip`。
5. 下载/访问 `master.zip` 或解压后的源码，搜索账号、密码、数据库配置、API key。
6. 用得到的低权限账号登录后台，继续上传/越权链（见关联卡）。

## PoC

```bash
# 1) 解码首页链接中的 Base64 段
python - <<'PY'
import base64
print(base64.b64decode("Y3RmL3VwZGF0ZS1rZXktcmVxdWlyZS1tYXhzaXRlLnBocA==").decode())
# ctf/update-key-require-maxsite.php
PY

# 2) 通过 require-maxsite 路由包含该文件，读取 key
curl -s "http://target/require-maxsite/Y3RmL3VwZGF0ZS1rZXktcmVxdWlyZS1tYXhzaXRlLnBocA=="

# 3) 用 key 触发更新/下载
curl -s "http://target/update-maxsite/?edge_key_release_2026"
```

## 变体与关联

- **路由变体**：其他 CMS 的 `require-*`/`include-*`/`load-*` 路由，常以 Base64/hex/序列化参数传递路径。
- **后缀变体**：`*-require-*.php`、`*.inc.php`、`*.tpl.php`；后缀白名单只限制名字，不限制内容。
- **泄露内容**：更新密钥、数据库配置、API key、SMTP 凭据、调试变量；更新器可能把 zip 解压到 webroot，导致源码/备份可下载。
- **关联卡片**：[[web-generic-xss-maxsite-upload-missing-authz-admin-page-exfil]]（同题后续低权限上传）、[[pentest-recon-git-directory-exposure-source-recovery]]（源码泄露恢复）、[[web-php-framework-laravel-ignition-debug-log-phar-rce]]（框架调试/源码泄露）、[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（编码绕过包含校验）。
- **边界**：若 `base_dir` 下没有可输出的 `*-require-maxsite.php` 文件、或更新端点校验 key/鉴权严格，链不成立；Base64 解码后的路径必须通过存在性/后缀/base_dir 校验。

## 检测与防御

- **移除敏感文件**：不要在 `base_dir` 下放输出密钥/配置的 `*-require-maxsite.php`；更新密钥只存服务端环境变量。
- **路由收紧**：`require-maxsite` 只允许固定模板白名单，不接受任意 Base64 路径；校验 realpath 与后缀，拒绝符号链接。
- **更新端点**：`/update-maxsite/` 加管理员认证、一次性 token、签名校验；更新包解压到非 webroot 目录。
- **检测信号**：`require-maxsite` 的 Base64 段频繁变化/指向 `ctf`、`config`、`update` 等目录；`/update-maxsite/` 带 key 参数访问；webroot 出现 `master.zip`/源码目录。

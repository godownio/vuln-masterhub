---
id: web-php-framework-cmsms-sqli-pwreset-token-smarty-function-rce
title: CMS Made Simple 链式利用：CVE-2019-9053 SQL 注入取回 pwreset token 重置管理员口令，再由设计师权限用 Smarty {function name=} 注入 RCE
type: scenario
domain: web
path: web/php/framework
technique: cmsms-sqli-pwreset-token-designer-smarty-function-injection
tags:
- php
- cmsms
- cms-made-simple
- sqli
- password-reset
- smarty
- ssti
- privilege-escalation
- rce
cve:
- CVE-2019-9053
- CVE-2021-26120
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: CMS Made Simple <= 2.2.15；Smarty < 3.1.39
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T11:24:50+08:00'
  notes: 已对照原文核对：CVE-2019-9053/CVE-2021-26120 标记与原文一致，affected_versions 依原文引文『CMS Made Simple 版本 <= 2.2.15、Smarty 3.1.39 之前』设定并去掉自加注释；rce.py 实测输出 nt authority\local service、图03 以 cslab 登录后台、图02 版本 2.2.9.1，链路有实测支撑；Smarty 注入具体片段内置于第三方脚本未公开，为未验证点，confidence medium 已注明。
url: /docs/web/php/framework/web-php-framework-cmsms-sqli-pwreset-token-smarty-function-rce/
draft: false
kb_aliases:
- CMSMS 未授权到 RCE
- CVE-2019-9053 + CVE-2021-26120
- moduleinterface m1_idlist 注入
- pwreset token 重置口令
- Smarty function name 代码注入
- CMS Made Simple 后台 getshell
---

## 一句话结论

CMS Made Simple 的 News 模块 `m1_idlist` 存在盲注（CVE-2019-9053），可把 `cms_users` 里的用户名、邮箱、口令哈希、salt 以及管理员的口令重置 token 一并注出；拿到 `pwreset` token 后无需旧口令即可改密登录后台，再给自己/目标账号加 Designer 权限，在模板里写 `{function name=...}`（CVE-2021-26120，Smarty < 3.1.39 编译期把 name 值拼进 PHP 代码）即得到服务器上的代码执行。

## 原理

- **注入点**：`moduleinterface.php` 把 `m1_idlist` 直接拼进 News 模块的 SQL（`... IN (a,b,1,5))`），末尾多余括号可被利用闭合原查询，形成布尔/时间盲注。原文环境里 `>` 被过滤，布尔注入需换 `BETWEEN` 之类的等价写法。
- **为什么能改密**：CMSMS 的找回口令流程把一次性 token 存进用户记录（`pwreset` 字段），校验时只比对 URL 里的 `rid` 与该字段。SQLi 能读到整行记录，token 就不再是秘密——攻击者拿到 `rid` + `uid` 直接访问 `pwreset.php` 即可设置新口令，等于绕过了「知道旧口令 / 能收邮件」两个前提。
- **为什么要进后台**：CVE-2021-26120 的触发面在模板编译，进入后台且具备 Designer（设计/模板）权限才能编辑模板与样式表；所以拿管理员会话后要确认或提升到该权限组。
- **Smarty 注入为什么成立**：Smarty 3.1.39 之前，编译 `{function name="..."}` 时把 `name` 的值直接写进生成的 PHP 代码而没有转义，`name` 里带引号与分号就能跳出字符串、插入任意 PHP 语句；模板每次编译/渲染都会执行这段代码，因此是一次写入、持续生效的后门。
- **为什么整条链可自动化**：四步（注出记录 → 用 token 改密 → 登录 → 写模板）全部是确定性的 HTTP 请求，原文用一个脚本 `rce.py` 串起并直接回显命令输出（`nt authority\local service`），说明链在真实目标上一次跑通。

## 触发条件

- CMS Made Simple <= 2.2.15 且 News 模块启用、`moduleinterface.php` 可未授权访问（CVE-2019-9053）。
- Smarty < 3.1.39（CVE-2021-26120），且攻击者最终能获得 Designer 级后台权限。
- 站点未对 `moduleinterface.php` 做 WAF 拦截；注入可利用布尔/时间盲注逐字符取数（原文 `>` 被过滤，需要替代语法）。
- 目标用户表里存在带 `pwreset` token 的管理员记录，或攻击者可通过注入直接改写管理员口令哈希（等价路径）。
- 后台模板编辑功能未被禁用、模板目录可写。

## 利用步骤

1. 指纹：页脚 `powered by CMS Made Simple version x.y.z`、`/admin/login.php`、`moduleinterface.php` 是否存在。
2. 确认注入：`/moduleinterface.php?mact=News,m1_,default,0&m1_idlist=a,b,1,5))` 后接布尔/时间条件，比较响应长度或延时；被过滤字符改用 `BETWEEN`/`LIKE` 等替代。
3. 注出 `cms_users`：`username`、`email`、`password`、`salt`、`pwreset`（token）与 `user_id`；如哈希难解，直接走 token 路线。
4. 重置口令：访问 `/admin/pwreset.php?rid=<token>&uid=<user_id>`，提交新口令；用新口令登录 `/admin/login.php`。
5. 权限：在「用户管理 → 用户组」把自己加入 Designer（或编辑已有设计师账号），确保能改模板/样式表。
6. 植入：在 Layout → Design Manager 的模板或样式表中插入含 `{function name="<注入片段>"}` 的内容，保存并让页面渲染触发编译；随后访问前台页面执行命令。
7. 验证与维持：用命令回显确认执行身份（原文为 `nt authority\local service`），必要时把 payload 写进被频繁渲染的模板做持久化。

## PoC

```http
# 1) 注入点（原文形态，盲注）
GET /moduleinterface.php?mact=News,m1_,default,0&m1_idlist=a,b,1,5))%20AND%203332=3332--%20- HTTP/1.1
Host: target

# 2) 用注出的 token 重置口令
GET /admin/pwreset.php?rid=<PWRSET_TOKEN>&uid=<USER_ID> HTTP/1.1
Host: target

# 3) 登录后在模板中写入（Smarty < 3.1.39 编译期拼接）
{function name="<引号闭合 + PHP 语句>"}
```

```bash
# 原文使用现成脚本一键完成 1-3 步并回显命令
python3 rce.py <host> / "whoami"
# -> nt authority\local service
```

说明：原文未公开 `{function name=}` 的具体注入片段（内置在脚本里），此处只保留触发形态；实际使用需按目标 Smarty 版本自行构造并验证。

## 变体与关联

- 变体：不重置口令，直接通过注入 UPDATE 管理员 `password`/`salt`（需要堆叠或写权限），效果等价。
- 变体：无 Designer 权限时改用其它后台可写点（模块上传、语言包、附加样式表）落到可执行路径。
- 变体：CVE-2019-9053 也常被用来直接注出管理员哈希后离线爆破，属于同一注入点的另一条出口。
- 关联：[[web-generic-ssti-smarty-direct-rce-v4-v5-bypass]]（Smarty 非沙箱直接 RCE 与 4/5 严格模式绕过，本卡是其在 CMSMS 后台的具体触发面）、[[web-php-joomla-db-root-reset-admin-password-hash]]（同类「拿到写库能力后改管理员口令进后台」）。
- 边界：CMSMS 高于 2.2.15、Smarty 已升级到 3.1.39+、News 模块被禁用、`moduleinterface.php` 被拦截、或目标未启用模板编辑时，链上任一环断开即失败。原文依赖第三方脚本，未展示注入取数的原始响应，故 confidence 取 medium。

## 检测与防御

- 检测：`moduleinterface.php` 的 `m1_idlist` 出现 `)`、`--`、`BETWEEN`、`SLEEP`、长布尔表达式；同一 IP 对 `/admin/pwreset.php` 的异常访问（无邮件流程却带 `rid`）；后台模板内容中新出现 `{function name=` 或 `{php}` 类标签；模板文件被改写后前台出现异常进程创建。
- 修复：升级 CMSMS 到 2.2.16+ 并升级 Smarty 到 3.1.39+；对 `m1_idlist` 做整型数组白名单校验，禁止拼接；重置口令 token 一次性使用且短时效、绑定会话/IP。
- 加固：`moduleinterface.php` 限制来源或加 WAF 规则；后台强制二次认证；模板编辑权限收敛到极少数账号并留审计；Web 目录对 PHP 执行做最小化（模板目录不可执行）；部署文件完整性监控覆盖 templates/ 与 stylesheets/。

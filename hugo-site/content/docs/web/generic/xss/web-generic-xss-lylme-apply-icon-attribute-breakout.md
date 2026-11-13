---
id: web-generic-xss-lylme-apply-icon-attribute-breakout
title: LyLme Spage 收录申请 icon 字段存储型 XSS：strip_tags/addslashes 后在后台审核页属性逃逸注入 onload
type: scenario
domain: web
path: web/generic/xss
technique: stored-attribute-breakout-striptags-addslashes
tags:
- web
- php
- xss
- stored
- attribute-injection
- admin
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V516
  verified_at: '2026-11-11T11:53:13+08:00'
  notes: 已对照原文与图04/05：图04 申请表单 icon 填 " onload=alert(document.cookie)>，图05 admin/apply.php 收录管理页弹 document.cookie，证明存储型属性逃逸成立；原文 apply() strip_tags(daddslashes()) 与后台 echo '<img ... data-original="'.$res["apply_icon"].'" />' 代码一致，payload 不含 < 不被 strip_tags 删除。修正一处技术细节：原卡称 addslashes 的反斜杠会存进数据库不准确——MySQL 解析字符串字面量时会消费 \" 的反斜杠，入库为裸 "；已将原理与示例 HTML 改为 data-original="" onload=...（属性逃逸结论不变，即使保留反斜杠 HTML 中也不是转义符）。卡内『preg_match /^<svg*/ 分支』未写入但不影响主链。dedup：recommendation=new，候选 backend-script-style-blacklist、blacklist-attr-breakout-onmouseover、h3blog username 等均为不同产品/不同注入点，非同链；dup-scan.json 未涉及。与同系统反射 XSS 卡入口/sink 不同，各自原子。去留：保留并 verified。
url: /docs/web/generic/xss/web-generic-xss-lylme-apply-icon-attribute-breakout/
draft: false
kb_aliases:
- LyLme Spage 存储型 XSS
- 六零导航页 收录申请 XSS
- icon 属性注入
- data-original 属性逃逸
- strip_tags 绕过 onload
---

## 一句话结论

LyLme Spage 的收录申请接口 `apply/index.php?submit=post` 把 `icon` 等参数只做 `strip_tags()` + `addslashes()` 就入库；后台审核页 `admin/apply.php` 把 `apply_icon` 直接拼进 `<img ... data-original="<值>" />`，提交 `" onload=alert(document.cookie)>` 这种不含 `<...>` 完整标签的 payload 不会被 strip_tags 删除，HTML 属性解析时它会闭合 `data-original` 属性并新增 `onload`，管理员打开收录管理页面即触发存储型 XSS。

## 原理

- 申请入口（`apply/index.php`）校验验证码后调用 `apply($_POST['name'], $_POST['url'], $_POST['icon'], $_POST['group_id'], $status)`。
- `apply()`（`include/function.php`）对每个参数执行 `strip_tags(daddslashes($x))`：
  - `strip_tags()` 只删除完整的 HTML 标签（以 `<` 开头、`>` 结尾）；`" onload=alert(...)>` 没有 `<`，于是原样保留。
  - `daddslashes()` 是 `addslashes()` 封装，只在 SQL 字面量层给 `'`、`"`、`\`、NUL 前加反斜杠；MySQL 解析字符串字面量时会消费这些反斜杠，入库的仍是原始 `"`（即使某些模式保留了反斜杠，HTML 中反斜杠也不是转义符，仍会属性逃逸）。
- 审核页（`admin/apply.php`）：
  ```php
  echo '<img class="lazy" src="https://cdn.lylme.com/admin/lyear/img/loading.gif" data-original="' . $res["apply_icon"] . '" />';
  ```
  数据库里存的 `" onload=alert(document.cookie)>` 拼进去后：
  `data-original="" onload=alert(document.cookie)>" />`。
  HTML 解析时第一个 `"` 结束空的 `data-original` 属性，随后 `onload=alert(document.cookie)` 成为 img 的新属性，`>` 结束标签。懒加载脚本把 `data-original` 写入 `src` 后加载动作触发事件（原文审核页面成功弹 Cookie）。
- 危害：管理员打开「收录管理」即可执行脚本，可窃取后台 Cookie/会话、以管理员身份发请求；原文截图弹出 `document.cookie`。

## 触发条件

- 目标运行含该代码的 LyLme Spage 版本（原文未标注具体版本）；收录申请功能开启（`apply` 状态非关闭）。
- 攻击者能通过申请页面的验证码（authcode）校验，提交带 payload 的 icon。
- 管理员访问后台收录管理页面 `admin/apply.php` 审核申请。

## 利用步骤

1. 打开 `/apply/` 收录申请页，填写 URL/名称/分组，验证码按页面获取。
2. `icon` 字段填 `" onload=alert(document.cookie)>`（无需完整 HTML 标签）。
3. 提交后申请进入 `lylme_apply` 表，等待管理员在后台「收录管理」查看。
4. 管理员页面渲染时属性逃逸，脚本执行；可替换为窃取 Cookie/发起后台操作的 payload。

## PoC

```http
POST /apply/index.php?submit=post HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

authcode=<验证码>&name=1&url=http://www.xxx.com/logo.png&group_id=1&icon=%22%20onload%3Dalert(document.cookie)%3E
```

管理员侧渲染结果（概念）：

```html
<img class="lazy" src="https://cdn.lylme.com/admin/lyear/img/loading.gif" data-original="" onload=alert(document.cookie)>" />
```

## 变体与关联

- 变体：`" autofocus onfocus=...`、`" onerror=...` 等属性注入；若某些浏览器/懒加载不触发 onload，可换 `onerror` 并用无效 `data-original` 触发。
- 变体：同一未过滤字段进入其他后台页面（链接管理、分组管理）时同样可属性逃逸。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]——无 `<script>` 时的替代执行载体；本卡是「属性逃逸 + 事件处理器」在存储型场景的具体利用。
- 关联：[[web-generic-xss-lylme-apply-url-contenttype-override]]——同系统的反射型 XSS。

## 检测与防御

- 防御：输出到 HTML 属性时必须用 `htmlspecialchars($v, ENT_QUOTES)`（或模板引擎的上下文转义）；`strip_tags`/`addslashes` 不能替代输出编码。
- 防御：后台审核页对 icon 做 URL 合法性校验（只允许 http/https 图片地址），拒绝包含引号、尖括号、空格事件属性的值。
- 检测：申请数据中出现引号 + `onload`/`onerror`/`onfocus` 等事件属性组合；后台页面访问日志中出现异常脚本执行/会话异常。
- 检测：对用户可控字段入库前做 HTML 标签与属性语法审计，而非只在入口做 strip_tags。

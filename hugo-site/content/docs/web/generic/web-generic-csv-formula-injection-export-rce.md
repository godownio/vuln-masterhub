---
id: web-generic-csv-formula-injection-export-rce
title: 导出 Excel/CSV 未转义昵称导致公式注入与客户端 RCE
type: scenario
domain: web
path: web/generic
technique: csv-formula-injection-export-rce
tags:
- web
- csv-injection
- formula-injection
- excel
- dde
- export
- client-side
- rce
cve:
- CVE-2026-23873
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:28:52+08:00'
  notes: 已对照原文与截图核对：contestrank.xls.php 中昵称未过滤、普通用户改昵称 =1+2、导出 XLS 单元格显示 3（img/05）证明公式求值，CVE-2026-23873 与卡片一致；未验证点：DDE 载荷 =cmd|'/C calc'!A0 原文未实际执行（卡片已注明），现代 Excel 对 DDE 多有限制
url: /docs/web/generic/web-generic-csv-formula-injection-export-rce/
draft: false
kb_aliases:
- CSV 注入
- Excel 公式注入
- DDE 公式 RCE
- 导出功能公式注入
- 昵称公式注入
---

## 一句话结论

当导出功能把用户可控字段（如昵称）原样写入 Excel/CSV 单元格，且字段以 `=`、`+`、`-`、`@` 开头时，Excel 会将其当作公式解析；攻击者写入 DDE 公式（如 `=cmd|'/C calc'!A0`），管理员打开导出文件时即可在其主机上执行命令。

## 原理

- Excel/LibreOffice 打开 CSV/XLS 时，会把以 `=`、`+`、`-`、`@` 开头的单元格内容解释为公式，而不是纯文本。
- DDE（Dynamic Data Exchange）公式可以把外部程序调用嵌入公式，例如 `=cmd|'/C calc'!A0`；在允许 DDE 的 Excel 配置下，打开文件会提示或直接执行命令。
- 导出代码通常只做 HTML 转义（`htmlspecialchars`），这对 Excel 公式没有作用：HTML 实体不会阻止 `=` 被识别为公式起始符。
- 攻击链是“存储型”的：攻击者先把自己的昵称/队伍名/学校名改成公式，进入排行榜；管理员导出并打开文件时，公式在管理员工作站执行。危害发生在客户端而非服务器，但可导致管理员主机 RCE、凭据窃取或横向。
- 该问题不要求攻击者拥有后台权限，只要有一个能被导出展示的用户可控字段即可；案例中普通用户修改昵称即可。

## 触发条件

- 存在导出 Excel/CSV 的功能，且导出内容包含用户可控字段（昵称、队伍名、备注、学校等）。
- 导出逻辑未对以 `= + - @`（以及制表符/回车等）开头的字段加前缀转义。
- 管理员/教师会用 Excel/LibreOffice 打开导出文件，且未完全禁用 DDE/公式。
- 攻击者能让自己的记录出现在导出结果中（如参加比赛、提交代码、注册账号）。

## 利用步骤

1. 注册普通账号，进入用户信息编辑页。
2. 把昵称改为无害验证公式 `=1+2`（或 `=1+2` 形式），保存。
3. 参加任意比赛并提交一次代码，确保自己出现在排行榜/导出数据中。
4. 进入比赛排名页，点击“导出/Download”生成 XLS/CSV。
5. 用 Excel 打开，确认单元格显示计算结果 `3`，证明公式被解析。
6. 在授权测试中改用 DDE 载荷（如 `=cmd|'/C calc'!A0`）验证客户端命令执行；实际攻击可替换为下载/执行、窃取文件等。

## PoC

```text
# 昵称字段（无害验证）
=1+2

# 打开导出的 XLS 后，单元格显示 3，说明被当作公式求值

# DDE 命令执行载荷（仅授权环境验证）
=cmd|'/C calc'!A0
```

```php
// 典型的易受攻击导出逻辑（示意）
$nick = $row['nick'];
echo "<td>" . htmlspecialchars($nick) . "</td>"; // HTML 转义不能阻止 Excel 公式
```

```php
// 修复：对公式起始字符加单引号，强制按文本解析
$nick = $row['nick'];
if (preg_match('/^[=+\-@\t\r]/', $nick)) {
    $nick = "'" . $nick;
}
echo "<td>" . htmlspecialchars($nick) . "</td>";
```

## 变体与关联

- 变体：`+`、`-`、`@` 开头的公式；用制表符/回车/空格绕过只看首字符的过滤；`=HYPERLINK(...)` 钓鱼；`=WEBSERVICE(...)` 外带数据。
- 变体：导出为真正的 XLSX 时，若单元格类型被写成公式而非文本，同样触发；CSV 只是最常见载体。
- 变体：其他被导出的用户可控字段（队伍名、学校、备注、提交统计）都可作为注入点。
- 关联：[[web-generic-xss-unauth-stored-xss-hot-question]]（同为存储型、在他人浏览器/客户端触发的注入）；[[pentest-initial-access-office-macro-document]]（Office 文档投递与客户端执行）。
- 边界：现代 Excel 默认对 DDE 弹窗确认或禁用，实际利用取决于版本/策略；案例只演示了 `=1+2` 的公式求值，DDE 命令执行是标准延伸但未在文中实测。若导出时已加 `'` 前缀或使用纯文本单元格，则不成立。

## 检测与防御

- 检测：审计所有导出功能，检查用户可控字段是否以 `= + - @` 开头；对导出文件做公式扫描；监控昵称/队伍名等字段中出现公式/DDE 特征。
- 修复：导出前对以 `= + - @ \t \r` 开头的字段加单引号前缀，强制文本；使用真正的 XLSX 并将单元格类型设为字符串；对导出内容做统一编码。
- 加固：提醒用户不要直接打开不可信来源的表格；禁用/限制 Excel DDE；使用受保护视图；对导出功能加权限与审计。

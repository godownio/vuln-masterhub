---
id: ctf-forensics-pcap-php-session-search-id-idor-audit
title: pcap 与 PHP session 文件关联审计：非管理员用他人 search_id 查询的水平越权
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-php-session-search-id-idor-audit
tags:
- ctf
- forensics
- pcap
- http
- php-session
- idor
- audit
- search_id
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:18:12+08:00'
  notes: 已对照原文数据识别赛题2及图 20-25 核对：Wireshark 导出 JSON、http.cookie/http.file_data、search_id 与 PHPSESSID 聚合、session login_id/is_admin 判定一致；未复跑 pcap。
url: /docs/ctf/forensics/ctf-forensics-pcap-php-session-search-id-idor-audit/
draft: false
kb_aliases:
- 流量包 session 越权审计
- search_id 越权
- PHPSESSID 关联
- PHP session 反序列化解析
- 水平越权取证
- 非管理员查询他人记录
---

## 一句话结论

从 pcap 导出 HTTP POST 请求，提取 JSON 请求体中的 `search_id` 与 Cookie 中的 `PHPSESSID`，按 `search_id` 聚合访问过它的 session；再解析 PHP session 文件中的 `login_id` 与 `is_admin`，若某个非管理员 session 的 `login_id` 与它查询的 `search_id` 不同，即证明应用仅按请求参数返回记录、未做属主校验，存在水平越权（IDOR）。

## 原理

- PHP 默认 session 以序列化形式保存在服务端文件（如 `/var/lib/php/sessions/sess_<PHPSESSID>`）中，内容形如 `a:2:{s:8:"login_id";i:11111;s:8:"is_admin";b:0;}`：`login_id` 是当前登录用户，`is_admin` 是角色标记。
- 业务接口用请求体里的 `{"search_id":"123456"}` 选择要返回的记录；如果服务端只校验“已登录”而不校验 `search_id` 是否属于当前 `login_id`，任何登录用户都能读取他人记录。
- 审计时把两个数据源关联起来：pcap 提供“谁在请求哪个 search_id”（PHPSESSID + search_id），session 文件提供“这个 PHPSESSID 对应哪个 login_id、是否管理员”。当 `is_admin=0` 且 `login_id != search_id` 时，就是一次水平越权访问。
- 管理员查询任意 `search_id`、普通用户查询自己的 `search_id` 都属于正常；只有非管理员跨用户查询才需要标记。若同一 `search_id` 被多个不同 session 访问，应逐个核对访问者身份。
- 该方法的难点在数据提取：Wireshark 导出的 JSON 中，Cookie 在 `layers.http["http.cookie"]`，请求体在 `layers.http["http.file_data"]` 且为冒号分隔的十六进制字符串，需要先还原字节再解析 JSON。

## 触发条件

- 有包含 HTTP POST 请求的 pcap/pcapng，请求体为 JSON 且包含对象标识（本案例为 `search_id`）。
- 能获得对应的 PHP session 文件（`session_<PHPSESSID>` 或 `sess_<PHPSESSID>`），或能通过其他方式还原 session 中的 `login_id`/`is_admin`。
- 需要判断是否存在已发生的水平越权，或 CTF 题目要求找出越权访问的用户/session。

## 利用步骤

1. 用 Wireshark 过滤 `http.request.method == "POST"`，通过“导出分组解析结果”导出 JSON（包含 http 层）。
2. 逐包读取 `_source.layers.http` 下的 `http.cookie` 和 `http.file_data`。
3. `http.file_data` 是形如 `6a:30:49:54:70...` 的十六进制串，去掉冒号和换行后 `bytes.fromhex()`，再按 UTF-8 解码。
4. 用正则从请求体提取 `"search_id"\s*:\s*"(\d+)"`，从 Cookie 提取 `PHPSESSID`。
5. 建立 `search_id -> {session}` 映射；只保留被多个 session 访问的 id 作为重点。
6. 对每个 `PHPSESSID` 读取 `session_<id>`，解析 `login_id` 和 `is_admin`。
7. 标记 `is_admin == 0 且 login_id != search_id` 的组合；必要时再结合用户表确认账号身份。
8. 汇总越权用户，按题目/审计要求排序输出。

## PoC

最小审计脚本（省略异常处理）：

```python
import json, re, os
from collections import defaultdict

data = json.load(open("output.json", encoding="utf-8"))
access = defaultdict(set)
for pkt in data:
    http = pkt["_source"]["layers"].get("http", {})
    cookie = http.get("http.cookie", "")
    hex_body = http.get("http.file_data", "")
    if not cookie or not hex_body:
        continue
    body = bytes.fromhex(hex_body.replace(":", "").replace("\n", "")).decode("utf-8", "ignore")
    m = re.search(r'"search_id"\s*:\s*"(\d+)"', body)
    s = re.search(r"PHPSESSID=([^;]+)", cookie)
    if m and s:
        access[m.group(1)].add(s.group(1))

for search_id, sessions in access.items():
    for sid in sessions:
        path = "session_" + sid
        if not os.path.exists(path):
            continue
        text = open(path, encoding="utf-8", errors="ignore").read()
        login = re.search(r'"login_id";i:(\d+);', text)
        admin = re.search(r'"is_admin";b:([01]);', text)
        if login and admin and admin.group(1) == "0" and login.group(1) != search_id:
            print("越权:", login.group(1), "查询了", search_id, "session", sid)
```

## 变体与关联

- 标识字段不一定是 `search_id`，也可能是 `user_id`、`order_id`、`id`；session 格式也可能是 JSON handler 或 `sess_` 前缀。
- 身份来源可换成 JWT：从 Authorization 头解出 `sub`，与请求体对象属主比较；或使用多账号权限矩阵/LeakScore 自动检测。
- 与“HTTP 未授权 API 审计”的区别：未授权审计看请求是否完全没有认证；本场景是“已认证用户越权访问他人对象”，需要 session 身份与对象属主两方关联。
- 与普通 IDOR 手工测试的区别：本场景基于历史流量取证，能还原已发生的越权行为，而不是主动构造请求。

## 检测与防御

- 服务端对每个对象访问做属主校验：用 session 中的 `login_id` 与记录属主比较，管理员才允许跨用户查询。
- 统一授权中间件，禁止仅凭客户端传入的 `search_id`/`user_id` 直接查询。
- 记录“谁在何时查询了哪个对象”的审计日志，并对非管理员跨用户查询告警。
- 会话文件与流量包属于敏感取证材料，应限制访问并加密存储。

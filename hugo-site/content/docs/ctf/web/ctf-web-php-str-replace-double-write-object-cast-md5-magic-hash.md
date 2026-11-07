---
id: ctf-web-php-str-replace-double-write-object-cast-md5-magic-hash
title: PHP 多阶段认证绕过：str_replace 双写 + POST 数组转对象属性 + MD5 魔术哈希
type: scenario
domain: ctf
path: ctf/web
technique: str-replace-double-write-object-cast-md5-magic-hash
tags:
- ctf
- web
- php
- filter-bypass
- str-replace
- type-juggling
- md5
- magic-hash
- auth-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:12:27+08:00'
  notes: 已对照原文与图01-03核对：?step1=11 回显结果 '11'、?step1=key 回显空串（str_replace 删除）、?step1=kkeyey 第一阶段成功 Master Const 1337 并提示 POST a 缺失（图03），与卡片一致；源码中 (object)$a->key === '1337' 与 md5($a)==md5($b) 严格不等条件、240610708/QNKCDZO 魔术哈希均与原文一致。未验证点：PoC 未本机复跑；CTF 环境无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/web/ctf-web-php-str-replace-double-write-object-cast-md5-magic-hash/
draft: false
kb_aliases:
- 消失的密钥
- str_replace 双写绕过
- kkeyey
- a[key]=1337
- PHP 数组转对象属性
- md5 魔术哈希
- 240610708 QNKCDZO
---

## 一句话结论

PHP 登录接口用 `str_replace("key","",$input) === "key"`、`(object)$_POST['a']->key === "1337"`、`md5($a) == md5($b)` 做三段校验时，可分别用双写 `kkeyey`、`a[key]=1337`、魔术哈希 `240610708`/`QNKCDZO` 通过，最终拿到凭证。

## 原理

- **str_replace 单次扫描双写**：`str_replace` 从左到右替换非重叠匹配。输入 `kkeyey` 时，中间的 `key`（第 2～4 个字符）被删除，首字符 `k` 与尾部 `ey` 重新拼成 `key`，因此 `$filtered === "key"` 成立；直接传 `key` 反而会被删成空串。
- **POST 数组转对象属性**：PHP 会把 `a[key]=1337` 解析成 `$_POST['a'] = ['key' => '1337']`；`(object)$a` 强转后得到 `stdClass`，`$obj_a->key` 即字符串 `"1337"`，与 `=== "1337"` 严格比较通过。若只传 `a=1337`，`$_POST['a']` 是字符串，`(object)` 后没有 `key` 属性，校验失败。
- **MD5 魔术哈希松散比较**：`md5("240610708") = 0e462097431906509019562988736854`，`md5("QNKCDZO") = 0e830400451993494058024219903391`。两者都是形如 `0e` 后接纯数字的字符串，PHP 的 `==` 会把两个数字字符串按数值比较，二者都等于 0，因此相等；而 `$val_a !== $val_b` 是严格字符串比较，两个原值不同，满足“值不同但哈希相等”的条件。
- PHP 8 收紧了“数字与非数字字符串”的比较，但两个数字字符串之间仍按数值比较，所以该 MD5 魔术哈希在 PHP 8 下依然成立。
- 这条链成立的关键是三个“语义差”：过滤器删除后的结果与比较目标相同、数组结构被强转成可预测对象属性、哈希比较使用松散比较而非 `hash_equals`。

## 触发条件

- 目标 PHP 应用存在多阶段登录/认证逻辑，源码或错误回显暴露了过滤与比较方式。
- 第一阶段对用户输入做 `str_replace` 后与关键字全等比较，且过滤器只做一次非重叠删除。
- 后续阶段把 `$_POST` 的数组参数用 `(object)`（或类似方式）强转后按属性读取，并使用严格比较。
- 存在两个用户可控参数经 `md5()` 后使用 `==` 比较，同时要求两个原始参数不相等。
- 攻击者能同时控制 GET 与 POST 参数（PHP 中 `$_GET` 与 `$_POST` 互不覆盖）。

## 利用步骤

1. 先传 `?step1=11` 观察回显，确认输入被处理且格式错误；再传 `?step1=key`，观察回显中的结果字符串变成空，说明存在关键字删除过滤。
2. 传 `?step1=kkeyey` 通过第一阶段，回显会给出下一阶段所需常量（示例为 `1337`）并提示缺少 POST 参数 `a`。
3. 构造 POST body `a[key]=1337`，满足 `(object)$a->key === "1337"`；若只传 `a=1337` 会得到类型/常量不匹配。
4. 在 URL 上追加第三阶段参数 `a=240610708&b=QNKCDZO`（GET 的 `a` 与 POST 的 `a[key]` 同时存在，互不冲突），使 `md5($val_a) == md5($val_b)` 成立。
5. 提交完整请求，响应返回最终凭证。

## PoC

```bash
curl -s "http://target/?step1=kkeyey&a=240610708&b=QNKCDZO" \
     -d "a[key]=1337"
```

```text
# 关键输入
step1 = kkeyey          # str_replace("key","",...) 后剩 "key"
POST a[key] = 1337      # (object) 后 $obj_a->key === "1337"
GET a = 240610708       # md5 = 0e462097431906509019562988736854
GET b = QNKCDZO         # md5 = 0e830400451993494058024219903391
                        # 0e... == 0e... 松散比较为 true
```

## 变体与关联

- 双写变体：任何“删除内层关键字后首尾字符重新拼成关键字”的输入都可行；若过滤器是正则替换或循环替换直到不再变化，则双写失效。
- 对象属性变体：`(object)` 也可换成 `json_decode` 后按属性访问、`extract()`、`foreach` 取值等；核心是数组键被当成对象属性。
- 哈希变体：`md5($a) == md5($b)` 可换成 `sha1`、`hash('md5',...)` 与魔术哈希字典；也可利用 `md5([])`/`md5(null)` 等类型错误返回 `NULL` 使两个比较都成立。
- 关联：[[web-generic-auth-php-loose-comparison-token-0e-bypass]]（0e 松散比较绕过）、[[web-generic-auth-php-md5-loose-comparison-error-code]]（md5 与整数弱比较）、[[web-php-loose-numeric-prefix-score-bypass]]（数字前缀弱比较）。

## 检测与防御

- 检测：请求参数出现 `kkeyey`、`0e` 开头的魔术哈希、`a[key]=` 这类数组语法；同一会话在短时间内连续触发多阶段认证；响应中的调试回显暴露过滤后字符串。
- 防御：安全比较一律使用 `===` 或 `hash_equals()`；不要用“过滤后的值等于关键字”作为认证条件，应直接比对服务端保存的随机凭据；对 `$_POST` 参数做类型与结构校验，拒绝数组或对象注入；关闭错误回显与源码泄露。

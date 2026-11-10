---
id: crypto-prng-php-mt-srand-time-prefix-seed-prediction
title: mt_srand 以 Unix 时间戳前 7 位为种子导致 mt_rand 校验值可预测
type: scenario
domain: crypto
path: crypto/prng
technique: prng-time-prefix-seed-mt-rand-prediction
aliases:
- PHP mt_srand 时间戳种子
- 时间戳前 7 位种子预测
- mt_rand 令牌可预测
- 伪随机数种子可预测绕过校验
tags:
- prng
- mt19937
- seed-prediction
- php
- mt-srand
- timestamp
- token-prediction
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-5
  verified_at: '2026-11-08T01:19:21+08:00'
  notes: 已对照原文核对：give!me!money! 题 mt_srand 以 time() 前7位为种子、循环100次取 mt_rand、由响应 Date 头推算时间戳，PoC 与源码一致；dedup 的 merge 为自命中（top 候选即本卡自身），其余候选为 C srand 2FA、urandom、RC4 等不同链；未验证点：原文未附该题成功得 flag 的截图，但源码与本地复现脚本完整；CTF 题无受影响版本标记；PoC 未独立执行
---

## 一句话结论

服务端用 `mt_srand((int)substr((string)time(), 0, 7))` 把当前 Unix 时间戳的前 7 位当作种子，并固定循环若干次取其中一次 `mt_rand()` 作为校验值；种子可由响应 `Date` 头推算，攻击者在本地用同版本 PHP 以相同种子、相同调用次数复现，即可得到完全相同的校验值并通过验证。

## 原理

- PHP 的 `mt_rand()` 基于 MT19937，是确定性伪随机数发生器：同一种子、同一调用序列产生完全相同的输出序列。
- `substr((string)time(), 0, 7)` 取十进制时间戳前 7 位：Unix 时间戳约 10 位，前 7 位大约每 10^3 秒（约十几分钟量级，取决于位数）才变化一次，种子空间极小且完全由当前时间决定。
- 服务器时间通过 HTTP 响应 `Date` 头（或题目/应用其它时间回显）暴露，攻击者把该时间转成时间戳、取前 7 位即得种子。
- 校验值生成逻辑是固定循环（本题 `for($i=0;$i<=100;$i++)` 取第 100 次 `mt_rand()`）；只要在本地用相同 PHP 版本、相同种子、相同循环次数与取法重放，就得到相同 `mt_rand()` 值。
- 根因：用可预测的公开量（时间）作为 PRNG 种子，且把 PRNG 输出直接当作认证/校验令牌。

## 触发条件

- 校验/令牌/验证码由 `mt_rand()`（或 `rand()`）生成，且种子来自时间、时间戳前几位、或其它可预测值；
- 攻击者能获知（或较窄范围枚举）种子对应的时间（响应 Date 头、页面时间戳等）；
- 生成算法（种子处理、循环次数、取第几次输出）已知或可审计；
- 本地可运行与服务端相同 PHP 版本的 `mt_srand`/`mt_rand`（同版本保证 MT 实现一致）。

## 利用步骤

1. 审计源码，确认种子来源（如时间戳前 7 位）与取随机数的循环次数/位置。
2. 从服务器响应 `Date` 头（或题目给的时间）解析出 UTC 时间并转成 Unix 时间戳。
3. 取时间戳前 7 位作种子，本地用 PHP 以相同循环次数复现 `mt_rand()` 取目标值。
4. 在有效时间窗内提交该值作为校验参数 `c`，通过 `$c == $shenhe` 判断。

## PoC

```php
<?php
// 由响应 Date 头换算得到的时间戳
$timestamp = 1749371543;                 // 示例值，替换为实际值
$seed = (int) substr((string)$timestamp, 0, 7);
mt_srand($seed);
for ($i = 0; $i <= 100; $i++) {
    if ($i == 100) { $token = mt_rand(); }
    else { mt_rand(); }
}
echo $token;                              // 提交为参数 c
?>
```

```text
GET  ?id=d&money=<满足金额门槛>
POST c=<本地复现得到的 token>
```

说明：结构复现的通用脚本，种子取法/循环次数/参数名需按目标源码调整；不访问、不执行。

## 变体与关联

- 变体：种子用完整时间戳、`date('Ymd')`、进程 ID、小范围计数器时，可枚举邻近时间/计数器值批量撞令牌。
- 变体：循环次数不同、用 `mt_rand(min,max)`、或用 `shuffle`/`array_rand`/`str_shuffle` 生成结果时，按同一序列重放即可。
- 关联：[[crypto-prng-srand-time-seed-2fa-code-prediction]]（srand(time()) 预测 2FA）；[[crypto-prng-mt19937-clock-seed-wallet-key-recovery]]（MT19937 时钟种子恢复密钥）。

## 检测与防御

- 检测：代码审计搜索 `mt_srand(`/`srand(` 与时间、时间戳、可预测值组合；响应 `Date` 头暴露精确时间且令牌由 `mt_rand` 生成。
- 检测：短时间内大量校验请求尝试相邻种子对应的令牌。
- 防御：用 CSPRNG `random_bytes()`/`random_int()` 生成令牌/验证码；不要以时间或可预测值作 PRNG 种子。
- 防御：校验值绑定会话、加过期时间与尝试次数限制；令牌长度足够且服务端生成后立即失效。

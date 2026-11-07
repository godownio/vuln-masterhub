---
id: web-php-dujiaoka-admin-password-hash-reproduce
title: 独角数卡 dujiaoka 管理员口令哈希复现：固定盐 + bcrypt 替换登录
type: scenario
domain: web
path: web/php
technique: dujiaoka-admin-password-hash-reproduce
tags:
- web
- php
- dujiaoka
- bcrypt
- password-hash
- credential
- laravel
cve: []
severity: medium
confidence: medium
status: draft
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:33:46+08:00'
  notes: 核对图27-32与原文Q17-19：/admin、getHash cost=10、邮件配置与仪表盘V2.0.5均一致；但图28/29的getSalt源码与原文答案不一致——图中常量为base64_decode('xPfGJQaE1zE5d+8=')（解码11字节），按PHP 7.3实跑XOR得fAjL3X5CGRvg4HA=，而原文Q17答案为lAID2ktDeRlGbcg=；原卡PoC漏写J且称16字节，已修正常量与字节数并注明差异。盐值无法按原图代码复现，待作者核对源码版本；affected_versions原为2.0.5（仅仪表盘目标版本，非受影响区间）已清除。
url: /docs/web/php/web-php-dujiaoka-admin-password-hash-reproduce/
draft: false
kb_aliases:
- 独角数卡后台密码
- dujiaoka getSalt
- dujiaoka getHash
- bcrypt 固定盐
- 发卡站管理员口令
---

## 一句话结论

独角数卡（dujiaoka）后台口令是 `password_hash("admin" . getSalt(), PASSWORD_BCRYPT, cost=10)`，而 `getSalt()` 由硬编码字符串的 SHA-256 前 16 字节与固定 Base64 常量异或得到，跨安装固定；拿到源码后即可离线复现该“盐”，为任意口令生成合法 bcrypt 哈希并替换数据库中的管理员哈希，从而登录 `/admin`。

## 原理

- 源码中的 `getSalt()`：
  - `$a = 'sdahjklh1212jkljass'`；
  - `$b = hash('sha256', $a, true)`（32 字节二进制）；
  - `$c = substr($b, 0, 16)`；
  - `$d = base64_decode('xPfGJQaE1zE5d+8=')`（Base64 16 字符，解码后 11 字节）；
  - `$e[$i] = chr(ord($d[$i]) ^ ord($c[$i]))`，得到 11 字节盐。
  这不是随机盐，而是固定的“pepper”；同一份源码的所有部署得到相同值。原文答案为 `lAID2ktDeRlGbcg=`，但按图中代码在 PHP 7.3 实跑得到 `fAjL3X5CGRvg4HA=`，原文代码与答案不一致，复现时以目标源码/数据库为准。
- `getHash()`：`$salt = getSalt(); password_hash('admin' . $salt, PASSWORD_BCRYPT, ['cost' => 10])`。bcrypt 的随机盐由 `password_hash` 内部生成，所以每次输出不同，但都对应同一个口令 `admin` + 固定 pepper。
- 为什么可以替换登录：应用只校验“输入口令 + getSalt()”的 bcrypt 哈希是否等于数据库中的值。若攻击者能写数据库（SQL 注入、备份/配置泄露、容器卷写权限），把管理员记录的 hash 换成自己生成的合法哈希，即可用自选口令登录；不需要知道原口令。
- 为什么固定盐危险：pepper 硬编码在源码中，一旦源码/镜像泄露，所有部署共享同一 pepper；若数据库哈希也泄露，可离线用 `admin`+pepper 作为前缀对候选口令做 bcrypt 校验。
- 案例还暴露了后台路径 `ADMIN_ROUTE_PREFIX=/admin`、邮件发送人与 SMTP 配置，均来自 `.env`/后台配置；这些配置与哈希一起构成完整的后台接管条件。

## 触发条件

- 目标为独角数卡 dujiaoka（案例版本 2.0.5），且能获得其源码、容器镜像或 `getSalt/getHash` 代码。
- 能写入管理员用户表/配置（数据库写权限、SQL 注入、卷挂载、备份恢复等）。
- 或者能读取数据库中的管理员哈希，并希望离线校验候选口令。
- 后台登录路径已知（默认 `/admin`，可被 `ADMIN_ROUTE_PREFIX` 修改）。

## 利用步骤

1. 从源码/镜像/备份中定位 `getSalt()` 与 `getHash()`，确认硬编码字符串、Base64 常量与 bcrypt cost。
2. 用 PHP/Python 复现 `getSalt()`，输出 Base64 校验（案例 `lAID2ktDeRlGbcg=`）。
3. 选择新口令（案例用 `admin`），计算 `password_hash('admin'.getSalt(), PASSWORD_BCRYPT, ['cost'=>10])`；每次运行结果不同，任取一个合法哈希。
4. 通过数据库写原语更新管理员账号的 password 字段；若只能读，则用同一 pepper 对字典候选逐个 bcrypt 校验。
5. 访问 `/admin`，用新口令登录；若失败，检查是否还有二次校验、账号状态、缓存或配置中的额外 salt。
6. 清理操作痕迹并确认影响范围（管理员账号、订单、配置）；取证时保留原始哈希与修改前后记录。

## PoC

```php
<?php
function getSalt() {
    $a = 'sdahjklh1212jkljass';
    $b = hash('sha256', $a, true);
    $c = substr($b, 0, 16);
    $d = base64_decode('xPfGJQaE1zE5d+8=');
    $e = '';
    for ($i = 0; $i < strlen($d); $i++) {
        $e .= chr(ord($d[$i]) ^ ord($c[$i]));
    }
    return $e;
}

echo base64_encode(getSalt()), PHP_EOL;   // 原文答案 lAID2ktDeRlGbcg=；按本代码实跑为 fAjL3X5CGRvg4HA=
echo password_hash('admin' . getSalt(), PASSWORD_BCRYPT, ['cost' => 10]), PHP_EOL;
```

```sql
-- 仅在授权测试/取证环境中演示；替换为实际管理员记录
UPDATE admin_users SET password = '$2y$10$...' WHERE username = 'admin';
```

本卡不针对真实站点执行；案例中仅复现了盐与哈希。

## 变体与关联

- 其它 PHP 应用可能用 `md5($password.$salt)`、`sha1`、`crypt` 或 Laravel `Hash::make`；先确认算法与 cost。
- salt 可能来自 `.env`/数据库/安装时随机生成；若每安装不同，需从配置或数据库中读取。
- 后台可能有验证码、2FA、IP 白名单、登录审计；替换哈希不一定足够。
- 关联：[[web-php-framework-laravel-ignition-debug-log-phar-rce]]（Laravel 应用入口）、[[web-php-joomla-api-config-application-public-db-credential-leak]]（PHP 应用配置泄露）、[[defense-forensics-c2-server-sqlite-conf-artifacts]]（服务端配置与凭据取证）。
- 边界：若无法写数据库且哈希不可读，单靠源码不能登录；若应用使用 Argon2 或额外 pepper 来自服务端环境变量，需要相应调整。

## 检测与防御

- 开发侧：不要硬编码全局 pepper；使用每用户随机盐与标准 `password_hash`；把 pepper 放入受保护的 KMS/环境变量并支持轮换。
- 运维侧：数据库最小权限、备份加密、审计管理员哈希变更；后台强制 2FA、登录失败锁定、IP 白名单。
- 检测：监控 `admin_users.password` 的非正常 UPDATE、异常后台登录、`/admin` 路径扫描；对比配置与镜像哈希。
- 取证：保留原始数据库、源码、容器镜像与访问日志；记录哈希替换时间与来源 IP。

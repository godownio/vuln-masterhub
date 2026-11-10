---
id: crypto-aes-date-md5-fixed-iv-db-file-encryption
title: PHP AES-256-CBC 数据库文件加密的弱密钥：md5(日期) 作 key、sha256 常量前 16 字节作固定 IV，可按日期枚举还原
type: scenario
domain: crypto
path: crypto/aes
technique: aes-256-cbc-date-derived-key-fixed-iv-file-encryption
aliases:
- 日期派生密钥加密
- 固定 IV 数据库文件加密
- MySQL ibd 文件加密还原
- openssl_encrypt 文件加密
tags:
- php
- openssl
- aes-256-cbc
- weak-kdf
- fixed-iv
- mysql
- ibd
- ransomware
- decryption
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:07:23+08:00'
  notes: 已对照原文核对；clockup.php 的 md5(date) key、substr(sha256('DeepMountainsGD'),0,16) IV 与还原脚本逻辑一致；原文未写组件版本
---

## 一句话结论

用 `md5(当前日期)` 作为 AES-256 密钥、用 `sha256(固定字符串)` 的前 16 个十六进制字符作为 IV，对 MySQL 的 `.ibd` 文件逐个 `openssl_encrypt`，看起来像勒索加密，实际密钥空间只有“日期”几百种、IV 固定不变；防守方按文件修改/入侵时间枚举日期即可解出 key，离线还原数据库文件。

## 原理

- **key 派生过弱**：`md5("2023-11-18")` 返回 32 个十六进制字符，恰好 32 字节，PHP `openssl_encrypt(..., 'aes-256-cbc', $key, 0, $iv)` 直接把它当 AES-256 密钥使用。密钥只依赖加密当天的日期，不依赖任何秘密；已知或可推测日期时最多枚举一年 365 个候选。
- **IV 固定**：`substr(hash('sha256', '固定盐'), 0, 16)` 取的是十六进制字符串前 16 个字符（16 个 ASCII 字节），不是随机 IV；所有文件、所有日期共用同一个 IV，导致相同明文块得到相同密文块，也便于识别加密方案。
- **CBC + PKCS7 可验证**：正确 key 解密后 padding 合法（概率约 1/256 误报），再用 MySQL 页结构（页头、索引页类型、`infimum/supremum` 记录等）二次校验，即可从日期候选里唯一确定 key。
- **加密脚本遍历数据目录**：`scandir` 目标库目录，对每个文件 `file_get_contents` → `openssl_encrypt` → `file_put_contents` 覆盖；不删除文件、不改文件名，只让 MySQL 无法启动/读取，属于数据破坏型影响。
- **还原**：用相同 key/IV `openssl_decrypt` 回写，或复制出加密文件在本地解密后再替换；若文件被覆盖前有备份/ibd 副本，也可用备份比对。

## 触发条件

- 攻击者已能在 PHP Web 进程上下文执行代码（WebShell/恶意插件），且 PHP 装有 openssl 扩展。
- Web 进程对 MySQL 数据目录（如 `/var/lib/mysql/<db>`）有读写权限（弱权限配置）。
- 加密脚本使用日期等可预测输入派生 key，且 IV 固定/可推导。
- 防守方能获得加密脚本，或从文件时间/日志推断加密日期。

## 利用步骤

1. 攻击者投放加密脚本（可伪装成数据库相关 PHP 文件），遍历目标库目录。
2. 对每个文件读取内容，用 `md5(date('Y-m-d'))` 与固定 IV 做 AES-256-CBC 加密后覆盖写回。
3. 防守方发现 MySQL 无法启动/表损坏，定位异常 PHP 与 `.ibd` 高熵文件。
4. 从文件 mtime、Web 日志、脚本内容确定加密日期范围。
5. 对每个候选日期生成 key，解密任一 `.ibd`，用 padding 与 MySQL 页头校验；命中后批量解密还原。
6. 替换回数据目录，启动 MySQL 查询验证。

## PoC

```php
// 加密侧（结构示意）
$key = md5(date("Y-m-d"));
$iv  = substr(hash('sha256', '<固定盐>'), 0, 16);
foreach (scandir($dir) as $f) {
    if ($f === '.' || $f === '..') continue;
    $p = $dir . '/' . $f;
    file_put_contents($p, openssl_encrypt(file_get_contents($p), 'aes-256-cbc', $key, 0, $iv));
}
```

```php
// 还原侧：枚举日期
$iv = substr(hash('sha256', '<固定盐>'), 0, 16);
foreach (['2023-11-17', '2023-11-18', '2023-11-19'] as $d) {
    $key = md5($d);
    $pt  = openssl_decrypt(file_get_contents('UserIdentity.ibd'), 'aes-256-cbc', $key, 0, $iv);
    if ($pt !== false && str_starts_with($pt, "\x00")) { // 再结合 MySQL 页头进一步校验
        file_put_contents('UserIdentity.dec.ibd', $pt);
        echo "key date: $d\n";
        break;
    }
}
```

## 变体与关联

- 变体：key 改为 `md5(日期+固定后缀)`，仍需枚举日期；若后缀随机且未知，则恢复难度上升。
- 变体：每文件随机 IV 并存放在文件头/旁路文件，固定 IV 特征消失；但 key 仍按日期派生时仍可枚举。
- 关联：[[crypto-aes-custom-kdf-md5-salt-iv-sha256-iter-db-decrypt]]（同为 md5/SHA-256 自建 KDF 的数据库密文还原）。
- 关联：[[defense-forensics-wcdb4-sqlcipher-offline-decrypt]]（数据库页级解密的校验与修复思路）。
- 关联：[[code-analysis-reverse-windows-ransomware-large-file-intermittent-encryption-three-128kb]]（真实勒索软件的密钥/加密结构对照）。

## 检测与防御

- 检测：Web 目录出现遍历 `/var/lib/mysql`、对 `.ibd` 调 `openssl_encrypt`/`file_put_contents` 的 PHP；数据库文件 mtime 集中变化且内容高熵；MySQL 启动报页校验错误。
- 检测：PHP 进程中 `scandir`+`openssl_encrypt` 组合、大量文件读写；Web 日志出现可疑脚本访问。
- 防御：Web 进程不得读写 MySQL 数据目录；数据库使用独立低权限账户；定期离线备份并验证可恢复性；部署 FIM 监控数据目录；发现加密后先保留样本再尝试日期枚举，不要直接重建库。

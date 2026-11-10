---
id: cmseasy-crossall-execsql-encrypted-sqli-admin-credential
title: CMSEasy crossall execsql 加密参数 SQL 注入泄露管理员凭证
type: scenario
domain: web
path: web/generic/sqli
technique: 加密参数 SQL 注入
tags:
- sqli
- cms
- php
- credential-leak
- admin-takeover
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-25
  verified_at: '2026-11-08T14:33:29+08:00'
  notes: 已对照原文与图01-02核对：crossall execsql 加密SQL请求回显admin+MD5(a66abb...46e8d)解出admin123456，证据链成立；原文未标注该SQLi受影响版本区间(7.7.5为靶机环境版本且针对文件上传项)，维持无versions；加密串生成工具CmsEasy_sql为公开仓库
url: /docs/web/generic/sqli/cmseasy-crossall-execsql-encrypted-sqli-admin-credential/
draft: false
kb_aliases:
- CmsEasy execsql 注入
- CmsEasy crossall 注入
---

# CMSEasy crossall execsql 加密参数 SQL 注入泄露管理员凭证

## 一句话结论

CMSEasy 的 `?case=crossall&act=execsql&sql=<加密串>` 接口接受用户可控的加密 SQL 并直接执行，攻击者可用公开工具生成加密串注入查询，直接返回管理员用户名与 MD5 密码哈希，解密后即可登录后台。

## 原理

该接口的本意是供站内模块跨表调用查询，`sql` 参数经其自定义算法加密后传入；服务端解密后未做任何语句校验或白名单限制就代入数据库执行，并以 JSON 回显查询结果。由于加密算法是公开可逆的（GitHub 上有现成的批量扫描/生成工具 CmsEasy_sql），攻击者可以在本地把任意 SELECT 语句加密后作为 `sql` 值提交，等于直接获得一个任意查询执行点。users 表中存有管理员账号及 MD5 密码哈希，一次查询即可全部带出。

## 触发条件

- 目标为 CMSEasy（实测配合 7.7.x 版本站点）且 `crossall`/`execsql` 入口未关闭；
- 攻击者可访问网站根路由（无需任何认证）。

## 利用步骤

1. 构造查询管理员表的 SELECT 语句，用 CmsEasy_sql 工具按站点算法加密成密文串；
2. 请求 `http://<target>/?case=crossall&act=execsql&sql=<密文>`；
3. 响应为 JSON，包含 `username`、`password`（MD5）等字段；
4. 将 MD5 哈希到在线彩虹表破解得到明文，用账号密码登录后台。

实测回显形如 `{"userid":"1","username":"admin","password":"<32位MD5>",...}`，MD5 解出明文后成功登录后台。

## PoC

见上节 URL 模式；加密串需用对应生成工具按目标算法产出，此处不给出可直接投递的完整密文。

## 变体与关联

- 拿到后台凭证后可与「后台模板保存任意文件写入」组合成完整 RCE 链；
- 该注入亦可用于任意表数据读取，不止于管理员表。

## 检测与防御

- 检测访问日志中对 `/` 携带 `case=crossall&act=execsql` 的请求；
- 升级 CMSEasy 或关闭 crossall 入口；对 `sql` 参数改为服务端预定义语句 ID 映射，禁止客户端传入原始语句；后台登录启用强密码与双因素，MD5 存储应换为 bcrypt/argon2。

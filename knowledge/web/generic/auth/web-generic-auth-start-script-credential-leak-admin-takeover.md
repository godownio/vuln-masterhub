---
id: web-generic-auth-start-script-credential-leak-admin-takeover
title: Web 根目录残留 start.sh 泄露数据库与管理后台凭据导致后台接管
type: scenario
domain: web
path: web/generic/auth
technique: exposed-start-script-credentials-admin-takeover
aliases:
- start.sh 泄露
- 启动脚本泄露凭据
- 部署脚本暴露
- 目录扫描拿管理员密码
- 硬编码管理员凭据
- 静态文件泄露密码
tags:
- web
- auth
- credential-leak
- information-disclosure
- static-file
- directory-scanning
- admin-takeover
- hardcoded-credentials
- docker
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V245
  verified_at: '2026-11-07T13:13:38+08:00'
  notes: 已对照原文与图14核对：扫目录发现 start.sh，内含 POSTGRES_DB=pastebin、POSTGRES_USER=pastebin_user、POSTGRES_PASSWORD=B236-9E9362319162、DB_* 同值及 ADMIN_USERNAME=admin、ADMIN_PASSWORD=92E54054-FD9C，与卡片完全一致；用 admin 凭据登录 Admin Panel（图14 URL /admin.php，Welcome admin!，All Pastes 中 flag{pzrHFUPRiZq4o08bcL6nsfmYyBgkSqN}），与卡片一致。卡片将“Web 根目录”作为推断场景、/admin.php 来自截图，均标注/可核。cve 空、无版本正确。dedup 与 debug config 泄露卡入口/文件不同，判 new 成立。未验证点：原文未给扫描工具与路径，PoC 为通用流程还原。
---

## 一句话结论

站点 Web 根目录残留了部署/启动脚本 `start.sh`，其中以明文 `export` 了 PostgreSQL 数据库账号密码以及 `ADMIN_USERNAME`/`ADMIN_PASSWORD`；目录扫描直接下载该文件后，用脚本里的管理员凭据登录 `/admin.php` 管理后台，即可读取后台中的 flag/敏感数据。

## 原理

- **部署脚本被当作静态文件提供**：`start.sh` 原本用于容器/主机启动时导出环境变量并拉起服务，但被放在了 Web 服务器可访问的目录（站点根目录或静态资源目录）。多数 Web 服务器对未知扩展名的文件默认按静态文件返回（`Content-Type` 可能是 `application/octet-stream` 或 `text/plain`），因此 `GET /start.sh` 即可拿到完整脚本内容。
- **脚本内含高价值秘密**：脚本为图方便把数据库连接信息（`POSTGRES_USER`、`POSTGRES_PASSWORD`、`DB_HOST` 等）和管理员初始化账号（`ADMIN_USERNAME=admin`、`ADMIN_PASSWORD=...`）以 `export` 明文写入；这些值通常与运行中的应用共享同一套配置。
- **凭据可直接复用**：应用的管理后台（本例 `/admin.php`）使用同一组 `ADMIN_USERNAME`/`ADMIN_PASSWORD` 初始化管理员账号；拿到脚本后用 `admin` + 明文口令即可通过正常登录流程进入后台。后台展示 flag（如 pastebin 的私有 paste），完成从信息泄露到管理员接管的闭环。
- **为什么目录扫描有效**：`start.sh` 不是常见入口，但字典中通常包含 `start.sh`、`docker-compose.yml`、`.env`、`entrypoint.sh` 等部署文件名；扫描器命中后返回 200 且内容可读，即可确认泄露。

## 触发条件

- Web 根目录/静态目录中存在 `start.sh`、`entrypoint.sh`、`.env`、`docker-compose.yml` 等部署文件，且服务器未禁止访问 `.sh` 或未知扩展名。
- 脚本中包含明文数据库凭据、管理员初始化账号或其他可复用秘密。
- 管理员账号在应用初始化时直接采用脚本中的值，未强制首次登录改密。
- 管理后台可从外网访问，且没有额外的 IP 白名单/二次认证。

## 利用步骤

1. 对目标做目录/文件扫描（如 `dirsearch`、`ffuf`、`gobuster`），字典包含 `start.sh`、`entrypoint.sh`、`.env`、`docker-compose.yml`、`*.sh`、`*.bak`。
2. 命中 `GET /start.sh` 后下载内容，检索 `PASSWORD`、`PASS`、`ADMIN`、`USER`、`DB_`、`SECRET`、`TOKEN` 等关键字，提取管理员账号密码与数据库连接信息。
3. 访问管理后台入口（如 `/admin.php`、`/admin`、`/login`），用提取到的凭据登录。
4. 在后台查看用户/订单/paste 等数据，读取 flag 或敏感信息；若数据库端口可达，也可用泄露的数据库凭据直连。
5. 若管理员口令被修改，可尝试同一脚本中的数据库凭据、其他环境变量或历史备份文件。

## PoC

```bash
# 1) 目录扫描命中部署脚本
curl -s http://TARGET/start.sh

# 2) 从响应中提取（示例字段）
#    ADMIN_USERNAME=admin
#    ADMIN_PASSWORD=<plaintext>
#    POSTGRES_USER=<dbuser>
#    POSTGRES_PASSWORD=<dbpass>

# 3) 用泄露的管理员凭据登录后台
curl -s -i -X POST http://TARGET/admin.php \
  -d 'username=admin&password=<plaintext>'
```

说明：原文只说明“扫目录发现 start.sh，里面有管理员账号密码”，随后登录 Admin Panel 取得 flag；具体扫描工具与请求路径未给出，PoC 按通用流程还原，后台路径/表单字段以目标为准。

## 变体与关联

- 变体：`.env`、`config.php`、`docker-compose.yml`、`entrypoint.sh`、`deploy.sh`、`Makefile`、CI 配置、备份文件（`*.sql`、`*.zip`、`*.tar.gz`）同样可能泄露凭据。
- 变体：脚本中的数据库凭据若数据库端口对外，可直接连库读取用户表、重置管理员口令或写入 webshell。
- 变体：`.git` 目录暴露时，可从历史提交中恢复被删除的配置文件与密钥。
- 关联：[[web-generic-auth-debug-config-credential-leak-hidden-resource-transition]]（调试配置泄露管理员凭据）、[[web-generic-auth-ai-api-debug-env-disclosure]]（调试接口泄露环境变量/连接串）、[[pentest-recon-dev-code-generator-db-credential-leak]]（信息收集阶段从开发残留获取数据库凭据）。
- 边界：若 Web 服务器显式拒绝 `.sh`/`.env`，或脚本只引用密钥管理服务而不含明文，则本条不成立；数据库/管理后台若只在内网可达，需先获得内网访问能力。

## 检测与防御

- 检测（黑盒）：请求 `/start.sh`、`/.env`、`/docker-compose.yml` 等，观察是否返回 200 与明文配置；检查目录列表是否开启。
- 检测（运维）：在 Web 根目录中检索 `*.sh`、`.env`、`*.yml`、`*.bak`、`*.sql` 等部署/备份文件；审查静态资源目录。
- 修复：部署脚本、环境文件、备份文件不得放在 Web 根目录；Web 服务器拒绝 `.sh`、`.env`、`.git` 等路径；Nginx/Apache 配置 `location ~ /\.` 与扩展名黑名单。
- 加固：密钥交由环境变量/密钥管理服务注入，不写入仓库与镜像；管理员初始密码随机化并强制首次修改；数据库不对外开放，后台加 IP 白名单与 MFA。

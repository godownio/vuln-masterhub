---
id: web-generic-nginx-missing-root-location-config-disclosure
title: Nginx 缺少 location / 时 server 级 root 生效：/cats/../nginx.conf 归一化后读取 /etc/nginx 配置
type: scenario
domain: web
path: web/generic
technique: nginx-missing-root-location-server-root-disclosure
aliases:
- Missing root location
- nginx root 全局生效
- 没有 location /
- /cats/../nginx.conf
- nginx.conf 配置泄露
- server 级 root 静态文件读取
tags:
- web
- nginx
- misconfiguration
- information-disclosure
- path-traversal
- static-file
- config-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T12:03:16+08:00'
  notes: 已对照原文与图01-03核对：server 级 root /etc/nginx、无 location /、/cats/../nginx.conf 与 /cats/../conf.d/default.conf 返回配置全文均一致；原理（归一化在 location 匹配前、server 级 root 静态兜底）成立。未复现，未验证不同 Nginx 版本对 .. 归一化的差异
---

## 一句话结论

Nginx 的 `server` 块在顶层写了 `root /etc/nginx;` 却没有定义 `location / { ... }` 时，未命中任何其它 location 的请求会由核心静态文件模块按 server 级 root 提供文件；请求 `/cats/../nginx.conf` 在 location 匹配前被归一化为 `/nginx.conf`，从而返回 `/etc/nginx/nginx.conf` 的完整内容，同理 `/cats/../conf.d/default.conf` 可读子目录配置。

## 原理

- **root 指令的作用域**：`root` 写在 `server` 块里时对没有自己 `root` 的 location 生效；它是“静态文件根目录”的默认值，不是访问控制。
- **没有 `location /` 不等于不提供静态文件**：Nginx 的 location 选择只有显式定义的 location；若请求不匹配任何 location，请求仍在 server 上下文中处理，核心静态模块会使用 server 级 `root` 拼接 URI 去找文件。因此缺少根 location 只是“没有为该前缀单独配置”，并不会关闭静态服务。
- **URI 归一化发生在 location 匹配前**：Nginx 会处理 `.`/`..` 路径段（默认 `merge_slashes on`、`disable_symlinks` 等另说）；`/cats/../nginx.conf` 归一化为 `/nginx.conf`，不再匹配 `location /cats`，于是落到 server 级静态处理，root 为 `/etc/nginx`，命中 `/etc/nginx/nginx.conf`。
- **为什么危害大**：`nginx.conf` 常包含 `include` 路径、`upstream`/内网地址、日志路径、`auth_basic_user_file` 指向的 `.htpasswd` 位置、TLS 私钥路径等；读取配置后可继续按路径读取 htpasswd、后端源码或内网信息。本题截图直接返回了 `nginx.conf` 与 `conf.d/default.conf` 全文。
- **与 alias 的区别**：本问题不依赖 `alias`，而是 server 级 `root` + 缺失 `location /` 的组合；`/cats/../` 只是用来让路径归一化后不命中已有的前缀 location。

## 触发条件

- `server` 块设置了顶层 `root`，且没有 `location / { ... }`（或没有覆盖所有未匹配路径的兜底 location）。
- 至少存在一个前缀/精确 location（如 `location /cats`）可供攻击者构造“先命中再穿越”的 URI；或直接请求 `root` 下已知文件。
- `root` 指向的目录包含敏感配置/密钥/凭据（如 `/etc/nginx`）。
- Nginx 静态文件模块正常工作，且请求路径可归一化到目标文件。

## 利用步骤

1. 从响应头、错误页或题目提供的信息确认 Nginx 版本与配置线索（本题 `nginx/1.27.0`）。
2. 直接尝试 `GET /nginx.conf`；若命中，读取完整配置。
3. 若 `/nginx.conf` 未命中已有 location，用前缀 location 构造穿越：`GET /cats/../nginx.conf`、`GET /cats/../conf.d/default.conf`，观察是否返回配置文件内容。
4. 从配置中提取 `include`、`upstream`、`auth_basic_user_file`、日志/证书路径与后端地址。
5. 按提取到的路径继续读取 `.htpasswd`、后端源码、私钥等；若配置暴露内网服务，评估进一步访问。
6. 记录请求、响应与配置内容作为证据。

## PoC

```bash
# 直接读 root 下文件（若未命中其它 location）
curl -s "http://<target>/nginx.conf"

# 通过已有 location 前缀 + .. 让 URI 归一化到 /nginx.conf
curl -s "http://<target>/cats/../nginx.conf"
curl -s "http://<target>/cats/../conf.d/default.conf"
```

危险配置示意：

```nginx
server {
    listen 5000;
    server_name ~(.+)$;
    root /etc/nginx;              # server 级 root，指向配置目录

    location /cats {
        alias /usr/share/nginx/html/;
    }
    # 没有 location / { ... } 兜底
}
```

安全的兜底写法：

```nginx
server {
    listen 5000;
    server_name ~(.+)$;
    root /usr/share/nginx/html;   # root 指向 Web 根，而不是配置目录

    location / {
        try_files $uri $uri/ =404;
    }
}
```

## 变体与关联

- **显式 `location /` 也不一定安全**：若 `location /` 的 `root` 仍指向 `/etc/nginx` 或允许 `..` 穿越，同样会泄露；关键是 root 指向与权限边界。
- **alias 变体**：`location /cats { alias /usr/share/nginx/html/; }` 无尾斜杠时 `/cats../` 可穿越到别名目录上级；见 [[web-generic-file-inclusion-nginx-alias-off-by-slash-traversal]]。
- **`try_files`/`index`**：`try_files $uri $uri/ =404` 会把归一化后的 `$uri` 交给静态处理；`index` 可列出目录默认文件。
- **默认站点**：Docker 官方 nginx 镜像默认 `root /usr/share/nginx/html`，若该目录可写或含备份文件也会泄露；但读取 `/etc/nginx` 需要 server 级 root 被错误设置。
- 关联：[[web-generic-auth-nginx-exact-location-deny-trim-bypass]]（同一篇文章的路径解析差异绕过）。

## 检测与防御

- **配置审计**：确保每个 `server` 都有显式的 `location /` 兜底，且 `root` 指向最小化的 Web 根目录；不要在 `server` 级把 root 指向 `/etc/nginx`、`/etc`、应用源码或家目录。
- **最小化静态面**：只暴露需要的静态目录；对配置目录、`.htpasswd`、私钥、日志目录设置 `deny all`/`internal`，并放在 Web root 之外。
- **权限**：Nginx worker 以低权限运行，配置与密钥文件权限限制为 root/nginx 可读；定期扫描 `nginx.conf` 中的 `root` 与 `alias` 组合。
- **检测**：访问日志中出现 `/cats/../nginx.conf`、`..` 段、对 `.conf`/`.htpasswd`/`.key` 的请求；静态路径返回 `text/plain`/`application/octet-stream` 的配置内容；同一 IP 在短时间内枚举配置/密钥文件名。

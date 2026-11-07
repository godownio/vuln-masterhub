---
id: web-nodejs-dokploy-certificate-path-traversal-file-write
title: Dokploy v0.26.6 certificates.create：certificatePath 路径穿越以 root 写 chain.crt
type: scenario
domain: web
path: web/nodejs
technique: dokploy-certificate-path-traversal-write
tags:
- dokploy
- nodejs
- path-traversal
- arbitrary-file-write
- certificate
- root
- trpc
cve: []
severity: high
confidence: high
status: verified
affected_versions: Dokploy v0.26.6（原文）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V33
  verified_at: '2026-11-05T06:01:53+08:00'
  notes: 已对照原文与7张截图核对：certificates.create 的 certificatePath 经 path.join(CERTIFICATES_PATH, ...) 归一化逃逸、mkdirSync recursive 后写固定文件名 chain.crt；img06/img07 确认写入 /tmp/dokploy_write_test_v2/chain.crt 内容 SECOND_VERIFICATION_CONTENT；卡内已注明固定文件名限制、需登录会话；affected_versions=v0.26.6 与原文一致，未在本机复现
url: /docs/web/nodejs/web-nodejs-dokploy-certificate-path-traversal-file-write/
draft: false
kb_aliases:
- Dokploy 目录穿越
- certificatePath 路径穿越
- certificates.create 任意文件写入
- Dokploy 任意文件写
- chain.crt 写入
---

## 一句话结论

Dokploy v0.26.6 的 `/api/trpc/certificates.create` 接受用户可控的 `certificatePath`，服务端用 `path.join(CERTIFICATES_PATH, certificatePath)` 拼接目录并 `fs.mkdirSync(..., {recursive:true})` 后写入 `chain.crt`；`path.join` 会归一化 `../`，攻击者用多级 `../` 可逃逸证书根目录，在任意可写目录（容器内以 root 权限）创建/覆盖固定名称 `chain.crt`，内容完全可控。

## 原理

- **路径拼接**：`packages/server/src/services/certificate.ts` 的 `createCertificateFiles` 取 `CERTIFICATES_PATH` 与 `certificate.certificatePath`，执行 `path.join(CERTIFICATES_PATH, certificate.certificatePath)`。`path.join` 不是安全边界：它会解析 `..`，把路径归一化到父目录，因此 `../../../../../../tmp/dokploy_write_test_v2` 会逃逸出证书目录。
- **递归创建 + 写入**：代码对 `certDir` 执行 `fs.mkdirSync(certDir, {recursive:true})`（自动创建多级目录），随后 `fs.writeFileSync(path.join(certDir, "chain.crt"), certificate.certificateData)`。文件名固定为 `chain.crt`，但目录与内容可控。
- **权限**：Dokploy 服务/容器以 root 运行（原文写入的文件属主为 root:root），因此可写入容器文件系统的任意可写目录；若挂载了宿主机目录或 Docker socket，影响面进一步扩大。
- **影响**：任意目录下创建/覆盖 `chain.crt` 可用于覆盖 TLS 证书链、写入被其它服务读取的配置/证书文件，或结合会在特定目录读取 `chain.crt` 的组件实现进一步利用；仅凭本漏洞不直接等于任意文件名写入或 RCE，需要目标存在读取/信任该文件名的路径。
- **权限说明**：接口为 tRPC 路由，PoC 携带有效会话 Cookie；属于认证后路径穿越（原文未明确是否 adminProcedure，按 PoC 需登录理解）。

## 触发条件

- Dokploy v0.26.6（或包含相同 `path.join(CERTIFICATES_PATH, certificatePath)` 逻辑的版本）。
- 攻击者拥有可调用 `certificates.create` 的会话。
- `certificatePath` 可控制且未做 `..`/绝对路径/白名单校验。
- 目标目录对 Dokploy 进程可写；容器以 root 运行时几乎任意目录可写。
- 需要写入的内容可控（`certificateData`）。

## 利用步骤

1. 获取有效会话，确认可调用 `certificates.create`。
2. 选择目标目录（如 `/tmp/dokploy_write_test_v2`），构造 `certificatePath` 为多级 `../` 加目标路径：`../../../../../../tmp/dokploy_write_test_v2`。
3. 设置 `certificateData` 为要写入的内容，`privateKey`/`name`/`organizationId` 补全为合法值。
4. 调用 `POST /api/trpc/certificates.create`，记录返回的 `certificateId`。
5. 进入容器/主机验证目标目录下是否生成 `chain.crt`，内容是否为 `certificateData`。
6. 评估可覆盖的敏感 `chain.crt`（TLS 证书链、服务配置）以及可写入目录的后续利用。

## PoC

```http
POST /api/trpc/certificates.create HTTP/1.1
Host: target:3001
Cookie: better-auth.session_token=<有效会话>
Content-Type: application/json

{
  "json": {
    "name": "second-verify-cert",
    "certificateData": "SECOND_VERIFICATION_CONTENT",
    "privateKey": "FAKE",
    "certificatePath": "../../../../../../tmp/dokploy_write_test_v2",
    "organizationId": "<organizationId>"
  }
}
```

验证：

```bash
docker exec <dokploy容器> cat /tmp/dokploy_write_test_v2/chain.crt
# SECOND_VERIFICATION_CONTENT
```

## 变体与关联

- 变体（路径深度）：`../` 数量按 `CERTIFICATES_PATH` 深度调整；也可尝试绝对路径（若 `path.join` 行为允许）或编码后的 `..`。
- 变体（目标目录）：`/tmp`、应用配置目录、Web 根、其它服务的证书目录；只要进程可写。
- 变体（文件名）：本漏洞固定写 `chain.crt`；若其它接口允许控制文件名，可组合为任意文件写入。
- 关联：[[web-nodejs-dokploy-destination-testconnection-rclone-command-injection]]、[[web-nodejs-dokploy-compose-appname-stored-command-injection]]（同一产品的 RCE 链）。
- 关联：[[web-generic-file-upload-adonisjs-bodyparser-filename-traversal]]、[[web-generic-file-upload-single-replace-dotdot-bypass]]（路径穿越/文件名控制的通用模式）。
- 边界：`certificatePath` 被白名单/`path.resolve` 前缀校验修复后失效；目标目录不可写、非 root 运行时影响降低；固定文件名限制了直接 RCE。

## 检测与防御

- 修复：对 `certificatePath` 做严格白名单（仅字母数字、连字符）；使用 `path.resolve` 后检查结果是否仍以 `CERTIFICATES_PATH` 为前缀（注意 `..` 与符号链接）；禁止绝对路径。
- 权限：Dokploy 以非 root 运行，证书目录使用专用低权限账户；容器只挂载必要的证书目录，避免宿主机敏感路径可写。
- 文件系统：证书目录与系统/应用配置目录隔离；对 `chain.crt` 写入做审计与完整性基线。
- 检测：请求中出现 `../`、`..\\`、编码后的 `%2e%2e`；`certificates.create` 的 `certificatePath` 含路径分隔符；证书目录外出现 `chain.crt`；Dokploy 进程写非证书目录；文件属主/权限异常。
- 运营：审计所有 `path.join` 拼接用户输入的代码；对文件写入路径做统一的安全封装（baseDir + 相对路径 + 前缀校验）。

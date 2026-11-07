---
id: cloud-container-oci-whiteout-deleted-file-recovery
title: OCI 镜像 whiteout 层恢复被删除文件内容
type: scenario
domain: cloud
path: cloud/container
technique: oci-whiteout-deleted-file-recovery
tags:
- docker
- oci
- container
- forensics
- whiteout
- image-layer
- ctf
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:48:24+08:00'
  notes: 已对照原文「白洞」核对：OCI layout 的 manifest 四层 gzip tar、基础层 root/treasure.txt 内容为干扰、两个 whiteout 层分别写入 root/.wh.treasure.txt=flag{lay 与 root/.wh.hint.txt=er_cake}，PoC 按 digest 逐层 tarfile 打开并读取 .wh. 文件内容，拼接得 flag{layer_cake}，与原文脚本一致。未验证点：未拿到附件复跑；whiteout 通常为空、真实恢复需回看低层，卡片已注明边界；无版本/CVE；frontmatter 无 sources/source_url。
url: /docs/cloud/container/cloud-container-oci-whiteout-deleted-file-recovery/
draft: false
kb_aliases:
- Docker whiteout
- OCI 镜像层取证
- .wh. 文件
- 删除文件恢复
- 镜像层历史
---

## 一句话结论

当拿到一个 OCI image layout（`index.json` + `blobs/sha256/*` + 多层 gzip tar）时，逐层打开 tar，检查 `.wh.` 前缀的 whiteout 条目及其内容，可以恢复镜像构建历史中被删除的文件/片段；本题 `.wh.treasure.txt` 与 `.wh.hint.txt` 的内容拼接出 `flag{layer_cake}`。

## 原理

- **OCI 镜像布局**：`index.json` 指向 manifest，manifest 的 `layers` 数组按顺序列出各层 tar（通常是 gzip）。每层只记录相对上一层的增删改；最终文件系统是各层叠加的结果。
- **whiteout 语义**：Docker/OCI 用 `.wh.<name>` 条目表示“删除下一层的 `<name>`”，用 `.wh..wh..opq` 表示 opaque 目录（隐藏下层全部内容）。正常镜像里 whiteout 通常是空文件，被删文件的真实内容仍在较低层；取证时应同时查看 whiteout 条目本身和较低层。
- **本题的特殊点**：两个 whiteout 条目不是空文件，而是把 `flag{lay` 和 `er_cake}` 直接写在 `.wh.treasure.txt` / `.wh.hint.txt` 的内容里；普通解压工具可能把 `.wh.` 文件当作隐藏文件忽略或只列名，必须显式读取条目内容。
- **为什么能恢复**：tar 层是完整可读的归档，`tarfile` 会保留每个条目的名称和内容；按 manifest 顺序遍历所有层、过滤 `.wh.` 且 `isfile()` 的条目，即可拿到这些“被删除历史”的载荷。
- **边界**：真实镜像的 whiteout 通常为空，需回看较低层才能恢复被删文件；如果镜像使用 opaque 目录、压缩层损坏或 manifest 缺失，需要先修复/枚举 blobs；whiteout 内容也可能是恶意构造，读取时不要执行。

## 触发条件

- 拿到 OCI image layout 或 Docker save 导出的镜像目录；能读取 `index.json` 与 `blobs/sha256/*`。
- manifest 的 `layers` 完整，tar 层可解压；目标文件在某一层被 whiteout 删除，或 whiteout 条目本身携带数据。
- 需要恢复的是“被删除文件/历史片段”，而不是最终运行态文件。
- 有 Python `tarfile`/`gzip` 或 `skopeo`/`umoci` 等工具。

## 利用步骤

1. 确认目录是 OCI layout：`index.json`、`oci-layout`、`blobs/sha256/`。
2. 读 `index.json` 找到 manifest digest，再读 manifest 的 `layers` 列表。
3. 按顺序逐层 `tarfile.open(path, "r:gz")`，遍历条目：
   - 记录 `.wh.` 前缀的 whiteout 条目；
   - 如果条目是普通文件（`isfile()`），读取其内容；
   - 同时记录同层/下层的同名文件，用于恢复真实被删内容。
4. 把 whiteout 内容或从低层恢复的片段按顺序拼接，检查 flag/文件头。
5. 本题输出 `root/.wh.treasure.txt -> flag{lay`、`root/.wh.hint.txt -> er_cake}`，拼接为 `flag{layer_cake}`。

## PoC

```python
import json
import tarfile
from pathlib import Path

root = Path("whitehole")
manifest = json.loads(
    (root / "blobs/sha256/0f50260006a83e2f8f8b0571e2a2176a11f0318bc0e13f076868563f7e473520").read_text()
)

for layer in manifest["layers"]:
    digest = layer["digest"].split(":", 1)[1]
    path = root / "blobs/sha256" / digest
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            if ".wh." in entry.name and entry.isfile():
                print(entry.name, archive.extractfile(entry).read().decode())
```

输出：

```text
root/.wh.treasure.txt flag{lay
root/.wh.hint.txt er_cake}
```

## 变体与关联

- **变体（真实删除恢复）**：whiteout 为空时，按层顺序维护“当前文件系统视图”，在较低层找同名文件的内容；opaque 目录会屏蔽下层，需要特殊处理。
- **变体（Docker save）**：`docker save` 的 tar 包含 `manifest.json`、`repositories` 和层目录，解析方式不同但同样按层叠加。
- **变体（镜像历史）**：`docker history`/OCI `history` 字段可提供构建命令，结合层内容定位敏感文件。
- **关联卡片**：[[cloud-container-runc-fd-leak-escape]]（容器运行时逃逸）、[[binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe]]（容器共享页缓存）。
- **边界**：whiteout 内容不可执行；真实镜像的删除文件可能已被后续层覆盖/清理；镜像层压缩格式可能是 zstd（需相应解压）。

## 检测与防御

- **镜像构建**：不要把敏感数据写入镜像层后再删除——镜像历史仍保留层内容；使用多阶段构建、`.dockerignore`、构建后扫描。
- **取证**：对可疑镜像逐层扫描 `.wh.`、`.wh..wh..opq`、大文件、删除记录；结合 `docker history` 还原构建过程。
- **检测**：镜像扫描器应检查 whiteout 条目内容与低层残留；CI 中禁止把密钥/flag 写入任何层。
- **响应**：发现镜像泄露后吊销相关凭据、重建镜像并清理 registry 缓存。

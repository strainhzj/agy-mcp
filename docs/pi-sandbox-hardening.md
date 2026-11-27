# agy-mcp 宿主机安全加固与 Pi 沙箱接入修改方案及验收标准

- 仓库位置: `/srv/workspaces/agy-mcp`
- Fork 仓库: `https://github.com/strainhzj/agy-mcp` (`upstream`: `https://github.com/tphakala/agy-mcp`)
- 基线环境实测 (2026-11-26): `agy 1.5.17` (`/home/piagent/.local/bin/agy`), `/usr/bin/bwrap` 可用且支持嵌套, 宿主机 `go 1.24.4` (`GOTOOLCHAIN=auto`, `go.mod` 要求 `go 1.27`)

---

## 1. 目标与威胁模型

### 目标
让运行在沙箱内的 `piagent` 通过宿主机上的 `agy-mcp` (Streamable HTTP) 调用 `agy`, 实现:
1. **隔离宿主机个人凭据**: `piagent` 沙箱不挂载、不放行宿主机个人 `~/.gemini` 或相关 OAuth/ADC 凭据, 也无法通过 `agy-mcp` 回读个人敏感目录 (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gh`, `~/.pi/agent`)。`agy` 自身服务凭据的风险另行验收。
2. **防越权代理 (Confused Deputy)**: 即使沙箱内的 `piagent` 遭遇提示词注入并传入恶意工具参数, `agy-mcp` 也不能被利用来访问未授权路径、读取任意 schema 文件、读取或操纵其他项目的作业与会话, 或耗尽宿主机资源。
3. **低成本跟进上游**: 参数策略收口在 `internal/policy`, 未选择受保护部署且未设置策略时保持上游行为。
4. **分阶段交付**: 首版只上线单项目、单轮、只读委派, 但从首版就固定项目路由和作业归属。按 [§4.7](#47-实施阶段与扩展门禁) 扩展到多项目, 再逐项目开通原生多轮续接。

### 信任边界
- **不可信输入**:
  - 来自沙箱内 `piagent` 的所有 MCP 工具参数 (`prompt`, `cwd`, `dirs`, `json_schema`, `conversation_id`, `continue_latest`, `mode`, `sandbox`, `agent`, `model`, `timeout`, `dir`, `job_id`)。
  - **共享工作区内的文件内容**: `piagent` 对工作区拥有写权限, 被提示词注入后可在工作区内写入 `.agents/hooks.json`、`AGENTS.md` 或恶意符号链接。
  - **`mode` 的处理声明**: `mode` 归类为不可信输入。`pi` profile 在工具 Schema 中移除 `mode` 字段, 并在参数校验层拒绝任何携带 `mode` 键的请求 (含空串、`null` 与非字符串), 不依赖 `agy` 自身对模式参数的约束; 是否向 CLI 传递 `--mode` 仅由服务端策略决定 (见 §4.1 `ModePolicy` 与 §4.4)。
- **可信配置**: 宿主机进程启动参数与环境变量 (`AGY_MCP_*`)。
- **纵深防御原则 (已由 Phase 0 实测确认)**:
  - **MCP 层 (`agy-mcp`)**: 负责 HTTP 强鉴权、参数/路径边界 (含符号链接防逃逸)、`json_schema` 禁读文件、模型/代理/超时/并发上限、会话与作业隔离、子进程环境变量脱敏。
  - **宿主机 OS 隔离层 (强制必需)**: Phase 0 实测确认 `agy 1.5.17` 的内置文件工具、工作区 hooks 和当前环境下的 `--sandbox` 终端命令均可访问 `cwd` 外路径。必须限制整个服务的宿主机访问, 并在服务内分隔控制面 (MCP、作业归属和监管) 与 worker (`agy` 及其工具、hooks、子进程)。`cwd`/`dirs` 检查只约束参数, 不替代 OS 边界。
- **残余风险声明**:
  - 不得复用宿主机个人登录态、会话历史或 MCP 插件。worker 使用专用服务身份与独立 `HOME`。若服务凭据仍处于 `agy` 工具可读范围, 独立 `HOME` 只缩小影响范围, 不能保证服务凭据不被回传；上线前必须记录可用权限、撤销方式和是否接受该残余风险。

---

## 2. 上游现状审计 (基于源码核查)

通读当前代码后, 确认上游 `tphakala/agy-mcp` 已有能力与待补齐的安全缺口如下:

### 可直接复用的上游能力
- Loopback-only HTTP 绑定校验 (`main.go:checkLoopbackAddr`)
- Origin/CSRF 保护与常量时间 SHA-256 Bearer Token 鉴权 (`internal/mcptools/serve.go:withBearerAuth`)
- 同步等待 + 超时自动转异步 (`agy_run_sync`, `agy_run`, `agy_wait`, `agy_status`, `agy_cancel`) 与 MCP progress 心跳
- 落盘作业监管 (`internal/supervisor/supervisor.go`) 与进程组 `SIGTERM -> SIGKILL` 回收
- `denied_actions` 失败识别 (`internal/manager/status.go:487-489, 549-563`)
- `doctor` 预检 (`internal/manager/doctor.go`)

### 必须解决的 7 个安全与适配缺口
1. **HTTP 鉴权默认可选** (`main.go:118-131`, `internal/mcptools/serve.go:54`):
   - `AGY_MCP_HTTP_TOKEN` 为空时直接以 unauthenticated 模式启动。面对沙箱接入时应支持强制 fail-closed。
2. **`cwd` / `dirs` 无根目录白名单** (`internal/manager/manager.go:508-528`, `internal/manager/normalize.go:22-44`, `internal/manager/agents.go:41-46`):
   - `agy_run` / `agy_run_sync` 与 `list_agents` 允许传入任意 `cwd` / `dirs`; 省略 `cwd` 时回落到 `agy-mcp` 服务端自身工作目录。
   - `normalizeCwd` 对 `filepath.EvalSymlinks` 采用 best-effort 回落, 且 `filepath.Abs` / `filepath.Join` 会在符号链接解析前词法折叠 `..` (`internal/manager/normalize.go:51-56`), 不能直接充当安全校验。
3. **`json_schema` 可传入宿主机文件路径** (`internal/mcptools/tools.go:36`, `internal/manager/manager.go:1232`):
   - Phase 0 实测确认 `agy 1.5.17 --json-schema <path>` 会直接读取任意宿主机文件并在解析报错中暴露内容特征 (`invalid character 'C' looking for beginning of value`)。
4. **`--dangerously-skip-permissions` 硬编码且 `--sandbox` 由调用方决定** (`internal/manager/manager.go:1190-1225`, `README.md:64,162-174`):
   - `buildAgyArgs` 始终传入 `--dangerously-skip-permissions`, 且 `--sandbox` 仅当调用方传 `sandbox: true` 时才启用。
5. **跨工作区会话泄露、劫持与作业状态越权** (`internal/manager/sessions.go:40-82`, `internal/manager/manager.go:542-546`, `internal/manager/status.go:215`, `internal/manager/cancel.go:17`):
   - `list_sessions` 读取 `~/.gemini/antigravity-cli/cache/last_conversations.json`, 默认返回宿主机全部工作区的路径和最近 `conversation_id`。
   - `continue_latest` 会直接续接宿主机交互式会话; 显式 `conversation_id` 可跨项目续接非本服务创建的会话。
   - 若共享默认 `AGY_MCP_STATE_DIR`, `agy_status` / `agy_wait` / `agy_cancel` 及 `managed-only` 会看到宿主机其他 `agy-mcp` 实例创建的作业。
6. **子进程环境变量透传泄漏 `AGY_MCP_HTTP_TOKEN`** (`internal/manager/manager.go:730`, `internal/supervisor/supervisor.go:277`):
   - `StartJob` 与 `supervisor.Run` 直接把完整 `os.Environ()` 传给子进程, 导致 `AGY_MCP_HTTP_TOKEN` 暴露给 `agy` 及其启动的命令/MCP 插件。
7. **资源与超时上限偏宽 / 与 `DefaultTimeout` 及 Pi 默认值未对齐** (`internal/config/config.go:85-86`, `internal/mcptools/tools.go:44`, `internal/mcptools/run_sync.go:26`):
   - `DefaultTimeout` 固定为 `30m`, 单次 `timeout` 上限固定为 `24h`, `MaxConcurrency` 固定为 `4`。若仅限制 `MaxTimeout=20m` 而不同步下调 `DefaultTimeout`, 所有省略 `timeout` 的调用都会失败。
   - Pi MCP 默认单次请求超时 `60s`, `agy-mcp` 默认 `AGY_MCP_SYNC_WAIT_CAP=90s` (且非法值静默回落 `90s`), 需在运行配置中显式对齐并在 `doctor` 中展示。

---

## 3. Phase 0: 宿主机 `agy 1.5.17` 行为实测记录 (已完成)

以下结论均于 **2026-11-26** 在当前宿主机 (`/home/piagent/.local/bin/agy`, `agy 1.5.17`, `/usr/bin/bwrap`) 使用 `gemini-3.8-flash-low` 实测获得:

| 实测项 | 实测命令/条件 | 实测现象 (`MEASURED against agy 1.5.17`) | 对方案的结论 |
|---|---|---|---|
| **T1: 去掉 `--dangerously-skip-permissions`** | 不传 `--dangerously-skip-permissions`, 传 `--sandbox --disable-slash-commands --output-format stream-json` | `permission_mode` 为 `request-review`, **不会挂起阻塞**。`cwd` 内 `read_file`/`write_file` 及简单 `ls -l` 通过; 复合命令 (`pwd && echo ok`) 被自动拒绝, 退出码 `0`, 空 `response`, `denied_actions: [{"action":"command","display_name":"Bash"}]`。**但**内置 `read_file`/`write_file` 依然成功读写了 `cwd` 外的 `/tmp/agy-p0/outside/canary.txt` 与 `escaped_no_skip.txt`。另测 `--mode auto` 提示 `warning: --mode auto is not available for this account; continuing in the default mode.` | 提供 `AGY_MCP_DISABLE_SKIP_PERMISSIONS` 开关用于只读/配合 `settings.json` 白名单场景, **默认保持 `false`** (否则正常多步 shell 命令会被拒); 且明确**移除该标志不能防止内置文件工具越权**, 不可替代 OS 级隔离。 |
| **T2: `--sandbox` 终端与内置工具隔离边界** | `--dangerously-skip-permissions --sandbox`, 分别用 `run_command` 与 `read_file`/`write_file` 探测 `cwd` 外路径与外网 | 1) `run_command` 确实创建了独立 mount/net namespace (`mnt` 与 `net` ns ID 异于宿主机, `ip addr` 仅见 `lo`), **但**依然成功执行了 `cat /tmp/agy-p0/outside/canary.txt`、`ls ~/.pi/agent` (43 项)、`ls ~/.gemini/antigravity-cli` (6 项)、在 `/tmp/agy-p0/outside` 和 `/home/piagent/` 创建文件, 并通过宿主机代理环境变量 (`HTTP_PROXY`/`HTTPS_PROXY`) 访问了 `https://example.com` (`HTTP/1.1 200 OK`)。<br>2) 内置 `read_file`/`write_file` 完全不受 `--sandbox` 限制, 成功读取 `/tmp/agy-p0/outside/canary.txt`、`/home/piagent/.gitconfig`、`/home/piagent/.gemini/antigravity-cli/cache/last_conversations.json`, 并写入 `/tmp/agy-p0/outside/escaped_write.txt`。 | `AGY_MCP_FORCE_SANDBOX=true` 可保留作为额外收敛层, 但 **`--sandbox` 在当前宿主机上绝不是安全边界**。必须由外层 OS 隔离 (`bwrap` 或系统级 systemd + 专用用户/独立 `HOME`) 承担硬隔离职责。 |
| **T3: 工作区 `.agents/hooks.json` 逃逸** | 在工作区创建 `.agents/hooks.json` (`SessionStart` hook) + `--sandbox` | Hook 直接在宿主机上下文执行 (`uid=1001`), **完全绕过 `--sandbox`**, 读取了工作区外 `canary.txt` 并在工作区外创建了 `hook-outside-marker`。 | 由于 `piagent` 可写共享工作区, 外层 OS 隔离**必须包裹整个 `agy-mcp` + `agy` 进程树**, 才能保证即使恶意工作区 hook 执行也看不到宿主机敏感目录。控制面与 worker 分离部署 (§4.6) 后由双层各自承担: 控制面最小化宿主机文件视图, worker 侧以受控管线生成的只读快照与每作业 tmpfs 兜底。 |
| **T4: `--json-schema` 内联 vs 同名文件 vs 任意路径** | 1) `cwd` 存在同名文件 `{"type":"object"}` 时传 `--json-schema '{"type":"object"}'`<br>2) 传 `--json-schema /tmp/agy-p0/outside/canary.txt` | 1) 同名文件场景下 `agy` 优先按内联 JSON 解析, 未打开同名文件 (`structured_output: {}`)。<br>2) 任意路径场景下 `agy` 退出码 `1`, stderr 报错 `Error: invalid --json-schema: schema is not valid JSON: invalid character 'C' looking for beginning of value`, 证实会读取宿主机任意文件并泄露内容特征。 | 有效内联对象这一例通过。未验证语义无效的 schema 或外部引用, 不能将 `json.Valid` 当成不读取文件或联网的保证；受保护首版禁用该参数。 |
| **T5: 外层 `bwrap` 与内层 `agy --sandbox` 嵌套** | 1) `bwrap --dev-bind / / bwrap --ro-bind / / /bin/true`<br>2) `bwrap --dev-bind / / --tmpfs /tmp/agy-p0/outside --chdir /tmp/agy-p0/ws agy --dangerously-skip-permissions --sandbox ...` | 1) 嵌套 `bwrap` 返回 `0`。<br>2) `agy --sandbox` 在外层 `bwrap` 内正常完成 (`rc=0`), 内部执行 `ls -la /tmp/agy-p0/outside` 仅见空 tmpfs (`总计 0`), `canary.txt` 完全不可见。 | 当前环境下嵌套可以启动, 且测试中的单个目录被遮蔽。尚未验证最小挂载、控制面分隔、网络和回收；不得把此命令用作生产部署模板。 |

### T6 (前置实测项, 尚未实测): `agy 1.5.17` 原生 `conversation_id` 续接状态依赖

**目的与门禁**: 判定续接原生 `conversation_id` 是纯远端状态、依赖 `.gemini` 内最小本地文件子集, 还是与不可拆分的本地凭据/状态强耦合。在取得实测记录并标注 `MEASURED against agy 1.5.17` 之前, §4.7 Phase 3 的续接机制只能作为设计目标, 不得定为既定运行前提。

**实测步骤草案**:
1. 首轮基线: 以 staged 服务身份种子化全新 tmpfs `.gemini`, 执行含唯一随机标记 (如 `NONCE_T6_XXXX`) 的首轮任务, 记录返回的原生 `conversation_id`, 并在销毁前采集 `.gemini` 内新增/变更文件差分清单 (路径、大小、类型)。
2. 纯远端续接验证 (路径 A 判定): 销毁首轮 tmpfs, 换全新 staged 种子 tmpfs (不带任何首轮新增文件), 仅传入首轮 `conversation_id` 要求复述标记, 记录退出码、stdout/stderr 与复述准确性。
3. 最小本地子集验证 (仅在步骤 2 失败时执行, 路径 B 判定): 仅注入差分清单中不含凭据/settings/hooks 的最小会话元数据文件重测; 再换一份新鲜 staged 种子重测, 检验续接是否与 token 刷新状态耦合。
本项聚焦纯 `agy 1.5.17` CLI 与 tmpfs 行为; 控制面重启复测与跨项目句柄负控属控制面行为, 归入 §5.E 的 Phase 3.3 演练, 避免与「T6 先于实现」形成循环依赖。

**结论落档**: 记录具体版本、命令参数、退出码与文件差分摘要, 显式标注 `MEASURED against agy 1.5.17`; 依结果从三条路径中唯一选定一条回填 §4.7 Phase 3: 路径 A (纯远端状态)、路径 B (可分离最小本地子集)、路径 C (不可分离本地状态或强耦合凭据, 禁止为续接放宽 `.gemini` 每作业销毁策略)。

**关于 `mode` / `--mode` 的实测边界**: 当前 `pi` profile 默认在 MCP 层禁用客户端 `mode` 且不传 `--mode`, 不依赖 `agy` 对模式值的处理维持安全边界。若未来启用 `AGY_MCP_FIXED_MODE`, 必须先在 T1 补测: (1) `agy 1.5.17` 支持的合法 `--mode` 枚举值; (2) 传入该值相对省略 `--mode` 是否改变工具调用权限、自动审批行为或写操作门禁; (3) 非法 `--mode` 值的退出行为。未完成实测的值不得进入服务端白名单。

---

## 4. 详细修改方案

以下为目标设计, 不是当前已实现的配置。按 §4.7 分阶段交付；没有通过对应门禁的能力保持关闭。

### 4.1 新增独立策略包 `internal/policy`

新增文件:
- `internal/policy/policy.go`
- `internal/policy/policy_test.go`
- `internal/policy/policy_posix_test.go` (涉及 `os.Symlink` 的用例按 `AGENTS.md` 放 POSIX 专属测试文件, 基础路径/schema/选项测试跨 Linux/macOS/Windows 全平台运行)

核心结构与常量:
```go
type SessionPolicy string

const (
    SessionPolicyAllow       SessionPolicy = "allow"        // 默认, 保持上游行为
    SessionPolicyManagedOnly SessionPolicy = "managed-only" // Phase 3: 仅解析本实例签发且归属匹配的会话句柄, 禁 continue_latest 与 list_sessions
    SessionPolicyDisabled    SessionPolicy = "disabled"     // 禁用 list_sessions, continue_latest 与 conversation_id 续接
)

// MaxInlineJSONSchemaBytes bounds inline json_schema size when InlineJSONSchemaOnly is enabled.
const MaxInlineJSONSchemaBytes = 64 << 10 // 64 KiB

type Policy struct {
    AllowedRoots            []string      // 规范化(Abs + EvalSymlinks)后的根目录白名单; 空表示不启用受限模式
    DefaultCwd              string        // 可选: 调用方未传 cwd 时的默认工作目录(必须落入 AllowedRoots)
    ForceSandbox            bool          // 强制给 agy 传入 --sandbox, 忽略调用方 sandbox=false
    DisableSkipPermissions  bool          // 禁止向 agy 传入 --dangerously-skip-permissions (仅适合只读或配合 settings.json 白名单)
    InlineJSONSchemaOnly    bool          // 仅允许内联 JSON 对象作为 json_schema, 拒绝文件路径
    SessionPolicy           SessionPolicy // 会话访问策略: allow / managed-only / disabled
    DisableContinueLatest   bool          // 禁止 continue_latest=true
    DisableAgentSelection   bool          // 禁止调用方传 agent 参数
    AllowedAgents           []string      // 可选: 允许的 agent 名称白名单 (与 DisableAgentSelection 互斥/优先禁选)
    AllowedModels           []string      // 可选: 允许的 model id 白名单
    MaxTimeout              time.Duration // 单任务 timeout 上限 (0 表示沿用上游 24h)
    RequireHTTPToken        bool          // HTTP 模式下强制要求设置 HTTPToken, 否则启动失败

    Profile                 string        // 空(=default) 或 "pi"; 选择受保护部署 (AGY_MCP_PROFILE)
    ProjectManifestPath     string        // pi profile 必填: 项目清单 JSON 绝对路径 (AGY_MCP_PROJECT_MANIFEST)
    ProjectID               string        // 来自清单 project_id; 配置 AGY_MCP_PROJECT_ID 时须与之完全一致
    InstanceID              string        // pi profile 必填: 实例唯一标识, 写入 ownership.json (AGY_MCP_INSTANCE_ID)
    SnapshotFingerprint     string        // 来自清单; 配置 AGY_MCP_SNAPSHOT_FINGERPRINT 时须与之完全一致
    SnapshotRoot            string        // pi profile: 来自清单 snapshot_root, 经 EvalSymlinks + Abs 规范化保存 (宿主机侧校验目标)
    WorkerMount             string        // pi profile 固定 "/workspace": worker 内中性只读挂载点 (清单 worker_mount)
    DisableJSONSchema       bool          // pi profile 强制 true: 拒绝一切客户端 json_schema (含有效内联对象)
    SessionTTL              time.Duration // managed-only 会话句柄有效期, 独立于 JobTTL (AGY_MCP_SESSION_TTL)
    StateBudget             int64         // 作业存储磁盘预算字节 (AGY_MCP_STATE_BUDGET)
    HTTPGuards              HTTPGuards    // 空闲会话超时/会话数/在途/速率守卫 (AGY_MCP_HTTP_*), 字段同 §4.2 表
    AllowedHosts            []string      // pi profile 必填: 允许的 HTTP Host 头白名单, 须含已发布端点地址与本机监听地址 (AGY_MCP_HTTP_ALLOWED_HOSTS)
    Mode                    ModePolicy    // mode 参数策略, 见下
}

type ModePolicy struct {
    DisableClientMode bool     // pi profile 强制 true, 不可通过配置放宽
    FixedMode         string   // 空 = 不向 agy 传 --mode; 非空须命中 AllowedModes 且经 §3 T1 实测
    AllowedModes      []string // 服务端固定模式的静态白名单
}
```

**项目清单 (`project-manifest.json`, `pi` profile 必填)**: 由受控部署管线生成、控制面只读加载。字段: `schema_version` (恒 `1`), `project_id` (`^[a-z0-9][a-z0-9._-]{0,63}$`), `snapshot_root` (宿主机侧只读快照根绝对路径), `snapshot_fingerprint` (`sha256:<64 hex>`), `worker_mount` (`pi` profile 恒 `/workspace`), `read_only` (`pi` profile 恒 `true`)。启动校验 (全部 fail-closed, 任一失败在监听与恢复作业前终止启动): 清单文件必须存在、可读、严格 JSON 且无未知顶层字段, 且不得位于 `StateDir` 内 (避免控制面可删改与 `STATE_BUDGET` 统计混入); `snapshot_root` 必须为存在的绝对目录, 不得与 `StateDir` 相同或互为父子目录; `AGY_MCP_INSTANCE_ID` 非空且 `StateDir` 为实例专用目录 (权限 `0700`); 可选的 `AGY_MCP_PROJECT_ID` / `AGY_MCP_SNAPSHOT_FINGERPRINT` 若配置, 必须与清单对应字段完全一致。归属校验: 任何读取结果、修改状态、续接或幂等重放, 都从磁盘读取作业 `ownership.json` (`profile`/`project_id`/`instance_id`/`snapshot_fingerprint`) 并与当前 `Policy` 逐字段比对, 不匹配一律返回同一拒绝错误, 不泄露他实例/项目作业的存在性与内容。

**`/workspace` 到 `snapshot_root` 的映射 (pi profile)**: `AllowedRoots`、`DefaultCwd` 与调用方传入的 `cwd`/`dirs` 统一使用 worker 视图的中性路径 `/workspace/...`。控制面进程运行于宿主机视图, 不存在 `/workspace` 挂载; 因此 `CheckDir` / `CheckExtraDirs` 在执行 `EvalSymlinks` / `Stat` 校验前, 先把路径的 `/workspace` 前缀映射为清单 `snapshot_root` 对应的宿主机真实路径再校验, 校验通过后写回 `req` 的仍是 `/workspace/...`, 确保 `meta.json`、`requestKey` 与传给 worker 的参数完全一致。非 `pi` profile 不做该映射。

> `last_conversations.json` 及任意历史作业里出现过的 agy 会话 ID 都不是授权依据。`allow` 仅用于上游兼容；`pi` profile 从 `disabled` 起步, `managed-only` 按 Phase 3 门禁另行启用。

关键校验规则 (全部 fail-closed):
1. **`ValidateAndNormalize()`** (启动时在 `config.Resolve()` 执行):
   - `AllowedRoots` 中每一项必须为**绝对路径**且为存在的目录, 经 `filepath.EvalSymlinks` + `filepath.Abs` 规范化后保存; 任一项相对路径、不存在、非目录或解析失败则启动报错退出。
   - `pi` profile 分支: `AllowedRoots` 必须仅含 `WorkerMount` (`/workspace`), 不对 `/workspace` 做宿主机存在性检查; 宿主机侧的目录存在性与 `EvalSymlinks` 校验作用于清单加载并规范化的 `SnapshotRoot`。
   - 若配置了 `DefaultCwd`, 必须通过 `CheckDir(DefaultCwd)` 校验并保存规范化结果。
   - `SessionPolicy` 必须为空或上述 3 个合法值之一, 非法值直接报错退出。
   - `MaxTimeout` 若非零, 必须满足 `0 < MaxTimeout <= 24h` (与 `mcptools.maxJobTimeout` 一致), 否则启动报错退出。
2. **`CheckDir(raw string)`**:
   - 若 `AllowedRoots` 为空: 不启用路径限制(返回空表示由调用方走上游原逻辑)。
   - 空 `raw`: 若配置了 `DefaultCwd` 则返回 `DefaultCwd`; 否则**直接拒绝** (禁止隐式回落到 `os.Getwd()` 所在宿主机目录)。
   - 非空 `raw`: **要求 `filepath.IsAbs(raw)`**, 拒绝相对路径 `cwd` (防止依赖服务端进程自身 `os.Getwd()` 解析或探测宿主机目录)。
   - **POSIX 符号链接顺序防绕过**: 先对原始 `raw` 调用 `filepath.EvalSymlinks(raw)` (不先做 `filepath.Abs`/`filepath.Clean`, 避免 `<allowed>/symlink-to-etc/..` 被提前词法折叠回 `<allowed>` 而绕过拒绝), 再对解析结果做 `filepath.Abs` 与 `os.Stat` 确认 `info.IsDir()`, 任一步失败直接拒绝(不做 best-effort 回落)。
   - 使用 `filepath.Rel(root, resolved)` 判断归属: 仅当 `rel == "."` 或 (`rel != ".."` 且不以 `".."+string(filepath.Separator)` 开头, 且 `!filepath.IsAbs(rel)`) 时放行, 防止 `/srv/workspaces/pi-evil` 前缀绕过; 非 `pi` profile `root` 为 `AllowedRoots` 项, `pi` profile `root` 为映射后的 `SnapshotRoot`。
   - **`pi` profile 路径映射与边界**: 先要求 `raw` 精确等于 `/workspace` 或以 `/workspace/` 开头 (须精确匹配路径段, 拒绝 `/workspace-evil` 之类相邻前缀), 再映射为 `<SnapshotRoot>/...` 按上一条顺序执行 `EvalSymlinks` -> `Abs` -> `Stat` -> 归属校验 (映射拼接必须复用不提前 `Clean` 的 `joinAsWritten` 或原始字符串拼接, 不得用 `filepath.Join`, 防止 `/workspace/symlink-to-etc/..` 在 `EvalSymlinks` 前被词法折叠绕过); 校验通过后以 `filepath.Join("/workspace", rel)` 拼回, 写回 `req.Cwd` 的仍是 `/workspace/...`。
3. **`CheckExtraDirs(cwd string, dirs []string)`**:
   - 若 `AllowedRoots` 为空: 原样返回 `dirs`。
   - 逐项校验: 拒绝空字符串与 root-relative 路径 (`rootRelative`)。
   - 相对路径使用不提前 `Clean` 的 `joinAsWritten(cwd, d)` 拼接, 然后对拼接后的原始路径先执行 `filepath.EvalSymlinks`, 再 `filepath.Abs`、`os.Stat` 验证为目录并校验落入 `AllowedRoots`, 防止 `<cwd>/symlink-to-ssh` 及 `<cwd>/symlink-to-ssh/..` 逃逸。
   - 返回规范化路径切片写回 `req.Dirs`: 非 `pi` profile 为宿主机物理路径; `pi` profile 为映射往返后的 `/workspace/...` (与 `CheckDir` 一致, 不向 `meta.json` 与 worker `--add-dir` 暴露宿主机路径)。
4. **`CheckJSONSchema(raw string)`**:
   - `DisableJSONSchema=true` (`pi` profile 强制): 任何非空 `raw` 直接以同一策略错误拒绝, 不做内联校验。
   - 非空且 `InlineJSONSchemaOnly=true` 时: `trimmed := strings.TrimSpace(raw)`, 检查 `len(trimmed) <= MaxInlineJSONSchemaBytes`, 且必须以 `{` 开头、以 `}` 结尾且 `json.Valid([]byte(trimmed))` 为 `true`, 否则以明确错误拒绝; 校验通过后返回 `trimmed` 并写回 `req.JSONSchema`。
5. **`CheckRunOptions(model, agent string, timeout time.Duration)`**:
   - `AllowedModels` 非空时: 若 `model == ""` (未指定且无 `DefaultModel`) 或不在白名单中, 拒绝; 否则放行。
   - `DisableAgentSelection` 为 `true` 时: 拒绝任何非空 `agent`; 否则若 `AllowedAgents` 非空且 `agent != ""` 且不在白名单中, 拒绝。
   - `MaxTimeout > 0` 且 `timeout > MaxTimeout` 时: 拒绝。
6. **`FilterModels` / `FilterAgents`**:
   - 提供给 `ListModels` / `ListAgents` 按白名单过滤返回结果 (若 `DisableAgentSelection=true`, `ListAgents` 返回空切片)。

---

### 4.2 配置层扩展 `internal/config/config.go`

在 `Config` 中增加 `Policy policy.Policy` 及可配置并发数 (`EnvMaxConcurrency = "AGY_MCP_MAX_CONCURRENCY"`), 策略解析仅在 `config.Resolve()` 中执行 (`ResolveWait()` 不受影响, 确保 `wait-job` / `hook-wait` 零额外依赖)。

所有新增环境变量使用 `AGY_MCP_` 前缀并导出常量供 `doctor` 复用; 联动覆盖统一使用 `os.LookupEnv` 区分"未设置"与"显式设为 `false`/其他值":

| 环境变量 | 未启用 `pi` profile 时的默认值 | `pi` profile 要求或默认值 | 说明 |
|---|---|---|---|
| `AGY_MCP_PROFILE` | (空, 不启用) | 必须显式设为 `pi` | 选择受保护部署；不由 `ALLOWED_ROOTS` 推断, 不满足前置条件则拒绝启动 |
| `AGY_MCP_ALLOWED_ROOTS` | (空, 不限制) | 必填且仅一个根, `pi` profile 下为 `/workspace` | 以 `filepath.ListSeparator` 分隔的绝对目录列表；配置此项只启用参数校验, 不代表 OS 隔离; `pi` profile 下控制面按 §4.1 映射规则把 `/workspace` 映射到清单 `snapshot_root` 后校验 |
| `AGY_MCP_DEFAULT_CWD` | (空) | 固定为 `/workspace` (worker 视图中性路径, 校验时映射到清单 `snapshot_root`, 见 §4.1) | 调用方省略 `cwd` 时的默认目录 (必须位于 `ALLOWED_ROOTS` 内) |
| `AGY_MCP_FORCE_SANDBOX` | `false` | `true` | 强制注入 `--sandbox`, 仅作纵深防御 |
| `AGY_MCP_DISABLE_SKIP_PERMISSIONS` | `false` | `false` | 不向 `agy` 传递 `--dangerously-skip-permissions`；此开关不保证只读 |
| `AGY_MCP_INLINE_JSON_SCHEMA_ONLY` | `false` | 不适用, profile 拒绝 `json_schema` | 其他部署可选择内联对象语法限制；受保护实例若要开放, 需另行验证 |
| `AGY_MCP_SESSION_POLICY` | `allow` | `disabled` 或 `managed-only` | `managed-only` 仅接受本实例签发的续接句柄 (机制为 §4.4 设计目标, 逐项目启用按 §5.E 门禁); profile 不接受 `allow` |
| `AGY_MCP_SESSION_TTL` | 不适用 (仅 managed-only 可设) | managed-only 未设时默认 `168h` | 句柄有效期, 独立于 `JobTTL`; 过期、换实例、换快照后明确拒绝; 非 managed-only 下设置直接报错 |
| `AGY_MCP_HTTP_SESSION_TIMEOUT` | 不设置 (空闲会话永不关闭) | 未设时默认 `15m` | HTTP 空闲会话超时; 显式 `<=0` 拒绝启动 |
| `AGY_MCP_HTTP_MAX_SESSIONS` | 不设置 (不限) | 未设时默认 `16` | 并发 MCP 会话上限 (超限 `429`); 依赖会话超时, 单独设置报错 |
| `AGY_MCP_HTTP_MAX_INFLIGHT` | 不设置 (不限) | 未设时默认 `8` | 处理中的 HTTP 请求上限 (超限 `503`) |
| `AGY_MCP_HTTP_RATE_PER_SEC` | 不设置 (不限) | 未设时默认 `20` | 每秒请求数令牌桶 (突发等于速率, 超限 `429`) |
| `AGY_MCP_STATE_BUDGET` | 不设置 (不限) | 未设时默认 `2GiB` | 作业存储磁盘预算; GC 超限按最老终态作业驱逐, 永不驱逐在途/不可归属作业 |
| `AGY_MCP_DISABLE_CONTINUE_LATEST` | `false` | `true` | 禁止 `continue_latest=true` |
| `AGY_MCP_DISABLE_AGENT_SELECTION` | `false` | `true` | 设为 `true` 时禁止调用方传 `agent` 参数且 `list_agents` 返回空切片 (避免用保留字 `none` 与真实 agent 名冲突); `pi` profile 默认禁选, 如需开放须另配 `ALLOWED_AGENTS` 白名单 |
| `AGY_MCP_ALLOWED_AGENTS` | (空, 不限制) | (空) | 逗号分隔的 agent 名称白名单 |
| `AGY_MCP_ALLOWED_MODELS` | (空, 不限制) | (空) | 逗号分隔的 model id 白名单 |
| `AGY_MCP_MAX_TIMEOUT` | 不设置, 沿用上游 `24h` | 必填 (示例 `20m`) | 显式值须满足 `0 < d <= 24h`, 若低于 `DefaultTimeout` (`30m`) 则同步下调默认值 |
| `AGY_MCP_MAX_CONCURRENCY` | `4` | `4` (生产推荐 `2`) | 单实例并发作业上限 (正整数, 非法值启动报错), 不代替宿主机资源上限 |
| `AGY_MCP_REQUIRE_HTTP_TOKEN` | `false` | 强制 `true` | HTTP token 为空则拒绝启动 |
| `AGY_MCP_STATE_DIR` | 上游默认 | 必须显式指定独立目录 | 绑定项目及实例, 仅控制面可访问；不可回落到默认或已有共享目录 |
| `AGY_MCP_PROJECT_MANIFEST` | (空, 不要求) | `pi` 必填 | 项目清单 JSON 绝对路径 (字段与校验规则见 §4.1); 缺失、非法或校验失败拒绝启动 |
| `AGY_MCP_INSTANCE_ID` | (空) | `pi` 必填 | 实例唯一标识, 写入每条作业 `ownership.json` 并参与归属校验 |
| `AGY_MCP_PROJECT_ID` | (空) | `pi` 可选 | 项目身份断言值, 仅用于与清单 `project_id` 交叉核验, 不一致拒绝启动; 不可替代清单 |
| `AGY_MCP_SNAPSHOT_FINGERPRINT` | (空) | `pi` 可选 | 快照指纹断言值, 与清单 `snapshot_fingerprint` 交叉核验, 不一致拒绝启动 |
| `AGY_MCP_SYNC_WAIT_CAP` | 上游默认 `90s` (非法值静默回落 `90s`) | `pi` 必填 (示例 `50s`), 非法值启动报错, 不静默回落 | 同步等待封顶; 仅 default profile 保留上游静默回落行为, `doctor` 回显生效值 (见 §4.4.6 与 §5.C) |
| `AGY_MCP_DISABLE_MODE` | `false` | `pi` 强制 `true` (设 `false` 拒绝启动) | 在工具 Schema 移除 `mode` 并拒绝任何携带 `mode` 的请求 (见 §4.1 `ModePolicy` 与 §4.4) |
| `AGY_MCP_FIXED_MODE` | (空, 不传 `--mode`) | `pi` 默认空 (可选) | 服务端固定模式; 非空值必须命中经 §3 T1 实测确认的静态白名单, 否则拒绝启动 |
| `AGY_MCP_HTTP_ALLOWED_HOSTS` | 不设置 (沿用上游 localhost Host 检查) | `pi` 必填, 须包含已发布端点地址 (桥接 Host) 与本机监听地址 | 允许的 HTTP Host 头白名单, 防 DNS rebinding 与跨端点滥用; 未命中返回 `403` |

> 关键修复: 当 `AGY_MCP_MAX_TIMEOUT` 小于默认 `DefaultTimeout` (`30m`) 时, `config.Resolve()` 自动将 `c.DefaultTimeout = c.Policy.MaxTimeout`, 防止省略 `timeout` 的正常请求因回落到 `30m` 而被 `MaxTimeout=20m` 误拒。

---

### 4.3 启动层拦截 `main.go`

- 在 `serve()` 中, 应用命令行覆盖后, 先校验 HTTP 绑定与最终 token, 再创建 manager、恢复历史作业或启动后台探针。`RequireHTTPToken` 下未配置 token 或以 `-http-token ""` 显式清空均拒绝启动。
- `pi` profile 必须由 §4.6 的受控启动器启动, 使用 HTTP、单项目快照及专用状态目录。未知 profile 值、缺项、配置冲突、状态目录归属不匹配或启动器检查失败均停止启动, 不回退到 stdio 或未隔离模式。项目清单在 `config.Resolve()` 加载并校验 (字段与规则见 §4.1), 校验失败同样在监听与恢复作业前终止启动。

---

### 4.4 Manager 层核心拦截点与环境变量脱敏 `internal/manager/`

不改动 `jobstore` / `streamjson` 核心落盘契约, 在 `internal/manager/` 的以下既有入口接入 `m.cfg.Policy`:

1. **`StartJob` / `normalizeRequest` (`internal/manager/manager.go:508-671`)**:
   - **路径校验**: 在 `normalizeRequest` 中, 若 `m.cfg.Policy.Restricted()`, 优先走 `Policy.CheckDir(req.Cwd)` 与 `Policy.CheckExtraDirs(req.Cwd, req.Dirs)`, 并将规范化后的 `cwd` / `dirs` 写回 `req`, 确保 `meta.json`、`requestKey` 与传给 `agy` 的 `--add-dir` 完全一致。
   - **Schema 校验**: `pi` profile 拒绝所有非空 `req.JSONSchema`。其他部署启用 `InlineJSONSchemaOnly` 时, 调用 `Policy.CheckJSONSchema` 并写回校验后的值。
   - **执行选项校验与强制覆盖**:
     - 若 `Policy.ForceSandbox`, 强制置 `req.Sandbox = true`。
     - 在 `DefaultModel` 回落与 `modelID()` 归一之后校验 `req.Model`; 校验 `req.Agent`; 在 `DefaultTimeout` 回落之后校验 `req.Timeout <= Policy.MaxTimeout`。
     - `Policy.Mode.DisableClientMode` (`pi` profile 强制 `true`) 时, 拒绝任何携带 `mode` 键的请求 (含 `null`、空串与非字符串), 且对外工具 Schema 不暴露 `mode` 属性; `mode` 键存在性检测 (缺省 / `null` / 空串 / 非字符串) 在 `internal/mcptools` 的原始 JSON 参数解包边界完成 (Go 强类型反序列化无法区分三者), 结果随请求传入 manager 执行拒绝; 服务端仅在 `Policy.Mode.FixedMode` 非空且命中经 §3 T1 实测的白名单时, 以独立参数 `["--mode", <FixedMode>]` 组装 CLI 参数, 永不透传客户端 `mode` 值。default profile 不做上述校验, 保持上游行为。
   - **会话续接策略**:
     - `Policy.DisableContinueLatest` 或 `SessionPolicy` 为 `managed-only` / `disabled` 时, 拒绝 `req.ContinueLatest == true`。
     - `SessionPolicy == disabled`: 拒绝非空 `req.ConversationID`, 不向 Pi 返回可复用会话字段。
     - `SessionPolicy == managed-only`: `req.ConversationID` 必须是控制面签发的不透明句柄。实例在首轮作业成功完成时把项目、实例、快照指纹、原生会话 ID、首作业 ID 和独立于 `JobTTL` 的到期时间持久化到状态目录 (`<stateDir>/sessions/`, 每句柄一个原子写入的记录), 输出端把原生 ID 一律改写为句柄; 输入端把句柄解析回原生 ID 交给 worker, 未知、畸形、其他部署或过期的值一律以同一策略错误拒绝 (原生 ID 本身永不被接受)。该机制为 Phase 3 设计目标, 逐项目启用按 §5.E 演练为门禁。
   - **`buildAgyArgs` 与 `requestkey.go` 兼容 (`internal/manager/manager.go:1190-1237`, `internal/manager/requestkey.go:99-109`)**:
     - 保留包级函数 `buildAgyArgs(req)` 作为默认包装 (`skipPermissions=true`), 新增 `buildAgyArgsWithSkipPermissions(req, skipPermissions)`。
     - `StartJob` 传入 `!m.cfg.Policy.DisableSkipPermissions`, `sameRequest` 同步接收 `skipPermissions`, 确保 `TestRequestKeyGolden`、`TestRequestKeyFieldsAreOmitempty` 和 `TestFindIdempotentJobAcrossBuilds` 全部通过。
   - **子进程环境变量隔离**: 受保护实例的所有启动路径使用统一的最小环境白名单, 包括 supervisor、实际 worker、版本探针 (`probeCmd`)、列表和用量探针。控制面 token 不进入 worker 的环境、命令行或可见文件。
2. **作业作用域校验**:
   - 受保护实例在创建作业时写入控制面确认的项目与实例归属。`Status` / `Wait` / `State` / `Cancel` 和幂等重放都在读取结果、修改状态或返回既有 `job_id` 前验证归属；未知和越界句柄返回同类错误。`meta.Cwd` 只能做附加校验, 不能替代归属记录。`wait-job` / `hook-wait` 保持宿主机本地用途, Pi 仅使用 MCP 查询, 不挂载状态目录。
   - 归属记录落盘为 `<stateDir>/jobs/<job_id>/ownership.json`, 字段固定为 `profile` / `project_id` / `instance_id` / `snapshot_fingerprint`, 与项目清单及当前 `Policy` 逐字段一致; 引用既有 `job_id` 或会话句柄的操作都从磁盘读取该记录并强校验, 缺失、解析失败或不匹配一律 fail-closed 返回同类拒绝, 不泄露他实例/项目作业的存在性与内容; 快照升级导致指纹变化时, 拒绝沿用旧快照上下文并返回明确的快照失效错误。
3. **`ListModels` (`internal/manager/models.go:254`)**:
   - 若配置了 `AllowedModels`, 按白名单过滤返回列表 (同时 `doctor` 的 `checkPolicy` / `checkAgyReachable` 若发现白名单过滤后为空, 给出明确 `WARN`)。
4. **`ListAgents` (`internal/manager/agents.go:41-51`)**:
   - 若 `DisableAgentSelection` 为 `true`, 直接返回空切片 (不额外 exec `agy`, 也不暴露宿主 agent 列表)。
   - 受限模式下对 `cwd` 执行 `Policy.CheckDir(cwd)` (空 `cwd` 若无 `DefaultCwd` 则拒绝), 并按 `AllowedAgents` 白名单过滤返回结果。
5. **`ListSessions` (`internal/manager/sessions.go:40-82`)**:
   - `SessionPolicy == disabled`: 直接返回明确 policy error。
   - `SessionPolicy == managed-only`: 同样返回明确 policy error, 不读 `last_conversations.json`；Pi 从首轮完成的作业结果获取句柄, 详见 Phase 3。
   - `SessionPolicy == allow`: 保持上游原行为, 不适用于 `pi` profile。
6. **`Doctor` (`internal/manager/doctor.go:105-119, 291-328`)**:
   - 新增 `policy` 检查项 (`checkPolicy`):
     - 未配置任何策略时返回 `PASS` (`unrestricted (default)`), 保证上游既有测试零影响。
     - 校验配置的根目录；在 `pi` profile 下, 缺少必需配置或状态目录归属不匹配应失败, 且校验对象是映射后的 `SnapshotRoot` 而非 `/workspace` 字面路径。明确提醒 `--sandbox` 不隔离内置文件工具与工作区 hooks, 本检查不代替实际部署验收。
   - 在 `checkConfigSources` 中展示生效策略来源、并发数、最大超时与 `AGY_MCP_SYNC_WAIT_CAP` 的解析状态 (**绝不打印 `AGY_MCP_HTTP_TOKEN` 明文**)。
   - 注: 当 `AGY_MCP_ALLOWED_ROOTS` 含不存在目录时, `agy-mcp doctor` CLI 在 `config.Resolve()` (`doctor.go:42-46`) 即 fail-closed 退出码 `1`; `checkPolicy` 本身亦做防御性校验以覆盖运行时目录被删或 Go 内直接构造 `Config` 的场景。

---

### 4.5 MCP 工具层最小改动 `internal/mcptools/`

- 保持现有工具名、字段类型、Annotations 与 `failure_reason` 闭集。在 `pi` profile 下的工具描述、字段说明、`serverInstructions` 和 README 一致说明项目路由、只读工作区、禁用参数与句柄含义, 不仅追加一段与上游说明冲突的提示。默认模式继续使用上游描述。
- pi profile 元数据措辞约束: `mcp.json` 的 `description`、工具与字段描述、`serverInstructions` 及 README 不得含 `coding tasks`、`edit files`、`modify workspace` 等写/执行导向文案, 统一采用只读委派表述 (如 "Read-only delegation for codebase analysis, research, and review against an isolated read-only snapshot")。`mode` 与 `json_schema` 在 `pi` profile 下从工具 Schema 移除; `conversation_id` 与 `continue_latest` 仅在 `SessionPolicy=disabled` (Phase 1/2) 下移除, `managed-only` (Phase 3) 启用时保留 `conversation_id` 字段并把描述限定为「仅接受控制面签发的项目内会话句柄」, `continue_latest` 始终移除。各禁用型参数的验收以「注入即拒、无落盘、不拉起 worker」为准 (见 §5.B.4)。

---

### 4.6 宿主机 OS 隔离部署与 Pi 侧接入方案 (强制必需)

Phase 1 只交付并验证一套 Linux 启动器及部署清单。可用系统级 systemd 托管并用 `bwrap` 定义 worker 的文件、进程和网络视图。无特权部署若要支持, 需独立通过同一验收；T5、专用 UID 或 `ProtectSystem=strict` 单独都不足以证明隔离成立。

- **控制面**: 最小化宿主机文件视图, 持有项目配置、只读程序、专用作业状态及入站令牌；这些状态和令牌不进 worker。由控制面监管 worker 并通过受控通道接收输出, 不信任 worker 自行声明的作业归属。
- **worker**: 使用与控制面分离的 OS 权限和进程视图, 只挂载必要的只读系统文件、固定版本的 `agy`、当前项目的只读快照和本实例所需的服务目录, 使用独立临时目录。采用挂载白名单, 禁止绑定宿主机全根目录；不挂载其他项目、个人配置、无关 socket 或控制面目录, 也不继承不需要的文件描述符。
- **网络与资源**: Pi 仅能访问鉴权后的指定 MCP 端点, worker 仅获访问模型及服务认证所需的受控出站 (部署采用 cgroup v2 BPF 出站白名单: unit 侧 `IPAddressDeny=any` 加专用放行地址, 任一负控目的地可达即判定该机制未生效, 不得开放端点)。限额落到具体项: HTTP 请求体上限 (上游 go-sdk 默认 4 MiB)、HTTP 会话/在途/速率守卫 (§4.2)、探针并发与输出上限、每作业输出落盘上限 64 MiB (超限截断并留截断标记)、作业存储 `AGY_MCP_STATE_BUDGET`、CPU/内存/PID 限额 (如 `MemoryMax` / `CPUQuota` / pids)。由 OS 回收整个 worker 组, 不只依赖 POSIX 进程组。首版服务重启时清理未结束 worker, 已完成结果仍可查询, 未完成作业标记为 `interrupted`。
- **发布物**: 固定 `agy` 版本、挂载和网络规则, 提供清单及启动/停机操作步骤。缺少隔离或资源限制则不对 Pi 开放端点；不提供裸跑回退。

#### Phase 1 配置示例 (由受控启动器注入)
```bash
AGY_MCP_PROFILE=pi
AGY_MCP_PROJECT_MANIFEST=/etc/agy-mcp/pi-instance/project-manifest.json
AGY_MCP_INSTANCE_ID=pi-review-01
AGY_MCP_STATE_DIR=/var/lib/agy-mcp/pi-instance
AGY_MCP_ALLOWED_ROOTS=/workspace
AGY_MCP_DEFAULT_CWD=/workspace
AGY_MCP_FORCE_SANDBOX=true
AGY_MCP_SESSION_POLICY=disabled
AGY_MCP_DISABLE_CONTINUE_LATEST=true
AGY_MCP_DISABLE_AGENT_SELECTION=true
AGY_MCP_DISABLE_MODE=true
AGY_MCP_MAX_TIMEOUT=20m
AGY_MCP_MAX_CONCURRENCY=2
AGY_MCP_SYNC_WAIT_CAP=50s
AGY_MCP_REQUIRE_HTTP_TOKEN=true
AGY_MCP_HTTP_ALLOWED_HOSTS=127.0.0.8:8765,192.168.5.45:8865
```

项目清单 (`project-manifest.json`, 只读 `0440`) 由受控管线生成: `snapshot_root` 指向宿主机侧快照目录, `worker_mount` 恒为 `/workspace`, `read_only` 恒为 `true`, `snapshot_fingerprint` 为快照内容指纹。快照必须由受控管线从可信基线生成, 不直接绑定 `piagent` 可写工作树; 入库时剥离 `.git/hooks`、`.agents/hooks.json` 等可执行钩子与越界符号链接后重算指纹; 快照刷新通过「生成新快照 -> 更新清单 -> 重启实例」生效, 不热切换。worker 视图内统一挂载为中性只读路径 `/workspace`, `ALLOWED_ROOTS` 与 `DEFAULT_CWD` 均以 `/workspace` 表达。每实例生成独立的高熵 Bearer Token, 只交给控制面及有权使用该项目端点的 Pi 客户端, 不写入启动命令、工作区或 worker 环境。

通过隔离检查后, 启动器内部的控制面监听参数为 (专用 loopback 地址, 与控制面 unit 入站白名单 `IPAddressAllow` 一一对应):
```bash
agy-mcp -http 127.0.0.8:8765
```

Pi 客户端不直连该监听地址, 必须经宿主机受控桥接转发 (链路与约束见下节「控制面与 Pi 的转发链路」)。

#### 控制面与 Pi 的转发链路 (双跳隔离)

控制面只监听实例专用 loopback (由启动器以 `-http` 注入, 禁止共享 `127.0.0.1`, 禁止绑定非回环地址); Pi 客户端不直连该地址, 经宿主机受控桥接转发:

```text
Pi 客户端
  -> 宿主机桥接端点 (示例 192.168.5.45:8865, 仅接收授权 Pi 网段入站)
  -> 桥接进程固定以 127.0.0.8 为源地址连接 127.0.0.8:8765 (命中控制面 unit 入站白名单 `IPAddressAllow`)
  -> 实例控制面 127.0.0.8:8765
```

- 桥接不旁路鉴权: 原样转发 `Authorization` 头, 不记录其明文; 转发请求的 Host 头为已发布端点地址时, 受保护 profile 按白名单放行 (`AGY_MCP_HTTP_ALLOWED_HOSTS`, 见 §4.2), Origin 校验与 Bearer 鉴权保持不变。该放行是对上游 DNS rebinding localhost Host 检查的受控收窄替代, 属目标设计; 允许的 Host 集合必须显式配置, 未命中一律 `403`。
- systemd unit 对控制面的可达来源仅限本实例专用 loopback 地址; 来自 `127.0.0.1` 等其他地址的访问一律拒绝。
- Pi 侧 `mcp.json` 禁止配置 `127.0.0.1:8765` 等控制面私有地址 (跨 netns 不可达, 且会诱使控制面退化到共享 loopback 破坏隔离)。

#### Pi 侧接入配置 (`~/.pi/agent/mcp.json`)
- 仅向 `piagent` 提供桥接端点与 Bearer Token, **沙箱白名单不放行 `~/.gemini`**:
  ```json
  {
    "mcpServers": {
      "agy_pi": {
        "url": "http://<桥接端点>:<端口>/mcp",
        "headers": {
          "Authorization": "Bearer ${AGY_MCP_PI_TOKEN}"
        },
        "timeout": 120,
        "description": "Read-only delegation for codebase analysis and review against an isolated read-only snapshot"
      }
    }
  }
  ```
- **网络连通前提**: 仅向 Pi 放行指定的桥接端点地址。若 Pi 与服务处于不同网络 namespace, 使用该端点的专用桥接, 不放开整个宿主机 loopback, 不共享 agy 登录目录。桥接不得绕过鉴权或记录 Authorization 头。worker 的出站边界见 §4.6 网络与资源: 每实例一个专用 loopback 地址, 其余宿主机 loopback 服务一律拒用。

### 4.7 实施阶段与扩展门禁

各阶段共用一个约束: **一个受保护实例只服务一个项目**。多项目通过增加实例实现, 不通过扩大 `AllowedRoots`、共享 `HOME` 或共享 `STATE_DIR` 实现。原生多轮会话限定在项目内；跨项目流程由 Pi 编排。

#### Phase 1: 单项目、单轮、只读

1. 用受保护的部署清单固定 `project_id`、`instance_id`、快照版本和 Pi 端点。身份由部署端决定, 不接收请求指定的项目身份。`instance_id` 在同一实例的正常重启间保持不变, 换实例或重建隔离边界时重新分配。
2. 在启动 worker 前, 把项目、实例、快照版本和 `job_id` 记录到仅控制面可写的状态中；幂等键按项目与实例隔离, 同一个键不得用于不同快照版本。由相同端点执行 `run`、`wait`、`status` 和 `cancel`。与上游模式或其他实例不共享状态, 不导入无归属的旧作业。
3. 只读挂载项目快照, `SessionPolicy=disabled`, 禁用 `json_schema`。需要追问时, Pi 在**同一项目**提交一个新单轮请求, 显式带上必要摘要, 不传原生会话 ID。

**进入 Phase 2 的条件**: §5.D 在实际启动器和 Pi 网络路径上通过。必须能复制项目清单并为新实例分配不同的身份、挂载、令牌和状态目录, 不改工具接口。

#### Phase 2: 多项目、单轮

1. 用 Phase 1 启动器部署第二个项目, 每项目独立 worker 身份、服务登录态与 `HOME`、快照、状态和 MCP 令牌；复用启动器, 不复用数据。每个实例单独设置资源上限, 宿主机另设总预算。
2. 保留 Phase 1 的项目端点名 (如 `agy_pi`), 在可信 Pi 配置为新项目增加独立端点和令牌引用；不让工作区配置覆盖此映射。Pi 先选被授权的项目端点, 再提交请求；后续操作发回该端点。项目无法确定时停下来确认, 不猜测 `cwd` 或回落到另一个端点。
3. 跨项目协作仍由 Pi 发起独立请求。只有获得授权时才把必要摘要作为新上下文送给目标项目, 不传其他项目的 `job_id` / `conversation_id` 或用 `dirs` 把两个项目拼在同一个 worker 里。Phase 3 也保持这一规则, Pi 按端点分别保存各项目会话句柄。

**进入 Phase 3 的条件**: §5.E 的双项目门禁通过。若一项目停机、升级或撤销令牌, 另一项目仍能独立运行。

#### Phase 3: 逐项目启用原生多轮

Phase 3 的句柄机制为目标设计 (`SessionPolicy=managed-only` + `AGY_MCP_SESSION_TTL`): 受保护实例在首轮作业成功完成时签发绑定项目、实例与快照指纹的不透明句柄, 持久化在控制面状态目录 (`<stateDir>/sessions/`), 输出只回句柄不回原生 ID, 输入只收本实例有效句柄 (未知、过期、其他部署、原生 ID 一律拒绝), 同会话串行; 跨重启续接、快照变更与换实例的允许/拒绝行为按 §3 T6 选定路径实现 (见第 3 点), GC 独立清理过期句柄。**隔离不变量 (不可为续接降级)**: worker 的 `.gemini` 为每作业新鲜 tmpfs, 种子自控制面管理的只读 staged 服务身份, token 刷新不跨作业, 作业结束即销毁且不回写种子目录; 只读快照挂载于中性路径 `/workspace`。但**逐项目开启 managed-only 仍以下述演练通过为门禁**, 且原生续接的实现路径受 §3 T6 实测结果门禁:

1. 完成 §3 T6 实测并归档 `MEASURED against agy 1.5.17` 结论, 在真实启动器上验证固定版本 `agy` 的首轮会话确实由本实例监管的作业创建 (worker 的 `.gemini` 为每作业新鲜 tmpfs, 缓存不含历史会话, 句柄来源即为可验证的本实例首轮)。
2. 试点启用 `managed-only` 后, Pi 用经授权的必要摘要新开首轮, 不迁移 Phase 1/2 的历史会话。已完成作业的结果 (例如 `agy_run_sync` / `agy_wait` / `agy_status`) 在现有 `conversation_id` 字段返回句柄而非原生 ID。Pi 等上一轮结束后在同一端点传回句柄；同一会话串行, 新一轮使用新的幂等键, 网络重试复用该轮键。
3. **续接是设计目标 (Phase 3.3), 按 T6 结论三选一冻结实现, 实测前不得定型**: 路径 A (T6 证明纯远端状态): 每轮仍分配全新 staged tmpfs `.gemini`, 仅经受控参数传入映射出的原生 `conversation_id`; 路径 B (T6 证明依赖 `.gemini` 内可分离的最小会话文件子集): 控制面按句柄维护独立私有子目录, 仅保存 T6 白名单确认的最小会话状态文件 (严格排除凭据/settings/hooks, 计入 `AGY_MCP_STATE_BUDGET`), 续接作业启动时注入新鲜 tmpfs, 结束时仅校验回存白名单变更; 路径 C (T6 证明依赖不可分离全量状态或跨作业 token): 关闭原生跨轮续接, 保持每作业新鲜 tmpfs 不变, 由控制面基于已落盘 `result.json` 构造摘要显式新开, 文档不宣称支持原生续接。同一实例且快照版本不变时, 选定路径为 A/B 的正常重启后可续接, 选定路径为 C 的重启后仍拒绝原生续接并按摘要新开; 切到新快照、会话过期、换实例或索引不可读时明确拒绝, 不自动续接别的历史; Pi 可用必要摘要显式新开。`continue_latest` 和 `list_sessions` 始终关闭。
4. **灰度与回滚**: §5.E 的多轮门禁通过后才逐项目启用。回滚时将该实例改回 `disabled`, 拒绝新的续接, 对在途作业按 §4.6 清理, 保留归属已验证的作业查询；不得回退到 `allow`、旧会话缓存或共享状态。

开放写工作区、schema 或统一多项目网关均不是进入 Phase 3 的前提, 需另行评审及验收。

---

## 5. 验收标准

### A. 编译、静态检查与上游回归门禁 (必须 100% 通过)
- [ ] `go build ./...` 零错误通过 (使用 Go 1.27 工具链)
- [ ] `go vet ./...` 零告警通过
- [ ] `go test ./... -race` 全量通过 (包含原有全部测试与新增策略测试, 零竞态)
- [ ] `go build -tags ruleguard ./rules/` 通过
- [ ] `golangci-lint run` 零问题通过 (如环境已安装)
- [ ] 未配置任何新增策略环境变量时, 上游全部既有测试 (`TestRequestKeyGolden`, `TestRequestKeyFieldsAreOmitempty`, `TestFindIdempotentJobAcrossBuilds`, `TestToolDefinitionsDeclareAnnotations`, `TestToolDefinitionsDescribeThemselves`, `TestFailureReasonSetDocumented`, HTTP/stdio 集成测试) 行为零退化

### B. 策略单元测试与安全对抗用例 (每条用例均需先验证删掉对应保护代码会变红)
1. **HTTP 强鉴权与配置校验**:
   - [ ] `AGY_MCP_REQUIRE_HTTP_TOKEN=true` 或启用 `pi` profile 时, 未提供 token 的 HTTP 启动在恢复作业或启动探针前失败。profile 缺项目清单、快照根或专用状态目录时也拒绝启动
   - [ ] 项目清单门禁: 缺 `AGY_MCP_PROJECT_MANIFEST`、文件不存在/不可读/非法 JSON/含未知顶层字段、缺 `project_id` / `snapshot_root` / `snapshot_fingerprint` 任一字段、`worker_mount` 非 `/workspace`、`read_only` 非 `true`、`snapshot_root` 不存在或与 `AGY_MCP_STATE_DIR` 重叠、`STATE_DIR` 权限过宽、缺 `AGY_MCP_INSTANCE_ID`、`AGY_MCP_PROJECT_ID` 或 `AGY_MCP_SNAPSHOT_FINGERPRINT` 与清单不一致: 全部拒绝启动
   - [ ] 合法配置启动并创建一条作业: 落盘 `ownership.json` 含 `profile` / `project_id` / `instance_id` / `snapshot_fingerprint`; 篡改任一字段后再查询或续接该句柄必须拒绝且不泄露作业数据
   - [ ] 非法配置组合拒绝启动: `AGY_MCP_HTTP_MAX_SESSIONS` 未配 `AGY_MCP_HTTP_SESSION_TIMEOUT`、非 managed-only 下设置 `AGY_MCP_SESSION_TTL` (按 §4.2 表注)
   - [ ] 其余 fail-closed 门禁: 缺 `AGY_MCP_HTTP_ALLOWED_HOSTS`、项目清单位于 `AGY_MCP_STATE_DIR` 内、`pi` profile 下 `AGY_MCP_SYNC_WAIT_CAP` 缺失或非法: 全部拒绝启动
   - [ ] 显式传 `-http-token ""` 同样被拒绝启动
   - [ ] 带正确 `Authorization: Bearer <token>` 返回 `200`, 缺省或错误 token 返回 `401`
   - [ ] `AGY_MCP_MAX_TIMEOUT=20m` 时, `cfg.DefaultTimeout` 自动下调为 `20m` (省略 `timeout` 的调用正常通过), 显式传 `25m` 被拒绝; `AGY_MCP_MAX_TIMEOUT=48h` 或 `<=0` 在 `config.Resolve()` 启动即拒绝
   - [ ] `AGY_MCP_STATE_BUDGET` 超限时 GC 驱逐最老终态作业, 永不驱逐在途/无终端标记/不可归属作业; HTTP 守卫各项 (空闲会话回收、会话数上限 `429`、处理中上限 `503`、速率 `429`) 生效且零配置时行为与上游一致
   - [ ] 用合成令牌验证 supervisor、worker 和所有探针 (包括冷启动版本检查) 的环境及 worker 的可见命令行、文件中均无控制面令牌
2. **路径白名单与符号链接逃逸防御**:
   - [ ] `cwd` 位于 `ALLOWED_ROOTS` 内: 允许通过并规范化为物理路径
   - [ ] `cwd` 为空且未设置 `AGY_MCP_DEFAULT_CWD`: 拒绝 (不回落到服务端 `os.Getwd()`)
   - [ ] `cwd` 为相对路径 (如 `subdir` 或 `../pi`): 受限模式下直接拒绝
   - [ ] `cwd` 指向白名单外路径 (如 `/home/piagent/.ssh`、`/home/piagent/.pi/agent`、`/tmp`): 拒绝
   - [ ] 前缀伪装攻击 (如白名单 `/srv/workspaces/pi`, 传入 `/srv/workspaces/pi-evil`): 拒绝
   - [ ] `..` 路径穿越 (如 `/srv/workspaces/pi/../../etc`): 拒绝
   - [ ] 符号链接逃逸 (`_posix_test.go`): 在白名单目录内创建指向 `/etc` 的 `link`, 传入 `<allowed>/link`、`<allowed>/link/..` 作为 `cwd` 或 `dirs` 均在先 `EvalSymlinks` 后拒绝 (不被词法折叠绕过)
   - [ ] `dirs` 中混入合法路径 + 越界相对路径 (`../other-repo`): 整体拒绝
   - [ ] `list_agents(cwd)` 传入越界目录、相对路径或符号链接逃逸目录: 拒绝; `DisableAgentSelection=true` 时返回空切片
   - [ ] `pi` profile 映射往返: 宿主机不存在 `/workspace` 目录时 `ValidateAndNormalize()` 正常启动, `/workspace/...` 校验通过且写回仍为 `/workspace/...`; `/workspace` 内指向白名单外的符号链接、`/workspace/<symlink>/..` 与 `/workspace-evil` 相邻前缀均被拒绝, `dirs` 的 `/workspace/...` 写回断言同 `cwd`
3. **`json_schema` 文件读取阻断**:
   - [ ] `pi` profile 拒绝所有非空 `json_schema`, 包括有效内联对象
   - [ ] 在不启用 `pi` profile 的内联限制模式下, 有效对象通过并写回 trimmed 值
   - [ ] 传入宿主机文件路径 (`/etc/hosts`, `~/.ssh/id_rsa`, `./schema.json`): 拒绝
   - [ ] 传入畸形 JSON、JSON 字符串 (`"/etc/hosts"`)、JSON 数组 (`[]`) 或超过 `64 KiB` 的超大 JSON: 拒绝
4. **CLI 标志强制锁定与模型/代理过滤**:
   - [ ] `ForceSandbox=true` 时, 调用方传 `sandbox: false` 或省略 `sandbox`, 最终生成给 `agy` 的 `args` 必然包含 `--sandbox`
   - [ ] `DisableSkipPermissions=true` 时, 最终 `args` 不包含 `--dangerously-skip-permissions`, 且 `sameRequest` 兼容测试通过
   - [ ] `AllowedModels` / `AllowedAgents` / `DisableAgentSelection` / `MaxTimeout` 越界请求均在 `StartJob` 入口拒绝, 不创建 job 目录、不占用并发槽位
   - [ ] `ListModels` 按 `AllowedModels` 过滤返回结果
   - [ ] `mode` 闭环: `pi` profile 下 `tools/list` 的工具 Schema 不含 `mode`; 分别以 `mode: "agent"`、`mode: ""`、`mode: null`、`mode: "--yolo"` 注入均在校验层拒绝, 不创建 job 目录、不拉起 worker; `AGY_MCP_DISABLE_MODE=false` 与白名单外 `AGY_MCP_FIXED_MODE` 均拒绝启动; 默认配置下合法请求落盘 `meta.json` 的 `args` 不含 `--mode`; default profile 不新增 `mode` 校验, 保持上游行为 (§1 目标 3)
   - [ ] `pi` profile 只读元数据一致性: `mcp.json` description、工具与字段描述、`serverInstructions`、README 不含 `coding tasks` 等写/执行类措辞, 工具描述、`serverInstructions` 与 README 写明禁用参数一律拒绝
5. **会话与作业隔离**:
   - [ ] `SessionPolicy=disabled` 时拒绝 `list_sessions`、`continue_latest` 和非空 `conversation_id`, 不回传原生会话 ID
   - [ ] `SessionPolicy=managed-only` 时: 首轮完成的作业输出句柄 (非原生 ID) 且重复读取句柄稳定; 运行中/失败的作业不产出句柄; 句柄输入解析回原生 ID; 原生 ID、未知句柄、畸形值、其他项目/实例/快照的句柄、过期句柄全部以同一策略错误拒绝; 同实例同快照重启后句柄仍可解析 (适用前提: T6 选定路径 A/B, 选定路径 C 时重启后拒绝原生续接), 换快照后拒绝; 过期句柄被 GC 清理, 未过期句柄与其他部署的句柄保留; `list_sessions` 与 `continue_latest` 始终拒绝
   - [ ] `Status` / `Wait` / `State` / `Cancel` 与幂等重放都拒绝外实例或无受保护归属记录的作业, 即使记录里的 `cwd` 一样；拒绝时不泄露其结果和标识符, 不修改其状态
   - [ ] Phase 3 中, 只接收本实例、当前项目及快照版本的有效句柄；拒绝原生 ID、未知、过期、其他项目或旧实例的句柄, 不读取 `last_conversations.json`

### C. `doctor` 诊断验收
- [ ] `agy-mcp doctor` 正常输出新增的 `policy` 检查项与配置来源 (含 `AGY_MCP_SYNC_WAIT_CAP` 与 `DefaultTimeout` 生效值), 退出码 `0`
- [ ] `doctor` 输出中绝不打印 `AGY_MCP_HTTP_TOKEN` 明文
- [ ] `AGY_MCP_ALLOWED_ROOTS` 配置了不存在目录时: `agy-mcp doctor` CLI 在 `config.Resolve()` fail-closed 报错 (退出码 `1`), 且单测直接调用 `checkPolicy` 对消失的根目录亦返回 `FAIL`
- [ ] `doctor` 明确区分配置检查与 OS 隔离验收；必需配置缺失或状态目录归属不匹配时失败

### D. Phase 1 单项目真实部署门禁
- [ ] **边界验证**: 用合成凭据和测试快照验证 Pi 及 worker 都不能访问宿主机个人数据、控制面私有存储或改写快照；worker 的内置工具、终端和 hooks 都不能读到 MCP 令牌 (Pi 只持其获授权端点的 Bearer Token)。未授权网络目的地被拒绝, 且负控必须包含本实例端点以外的宿主机 loopback 目的地 (IPv4 与 IPv6 各一, 如 `127.0.0.1:6379` 与 `[::1]:22`)：任一负控通过即判定 cgroup BPF 在该主机未生效, 不得开放端点。负控还必须包含: 经代理环境变量 (`HTTP_PROXY` / `HTTPS_PROXY`) 指向非白名单地址的出网尝试 (对应 T2 已实测的逃逸路径), 以及两条独立负控: worker 回连控制面端点 (`127.0.0.8:8765`, 优先断言网络层不可达, 否则须独立断言无令牌时不可用); 携带非白名单 `Host` 头的请求 (须 `403` 拒绝)。
- [ ] **agy 服务凭据残余风险 (独立判据)**: 用 worker 的内置工具与终端实测能否读取 staged 种子目录、worker HOME 及环境中的服务凭据; 若仍可读, 必须同时满足以下三项才判 PASS: 记录该凭据的最小可用权限范围、实测撤销流程 (轮换/吊销后旧凭据失效)、取得书面风险接受签字; 任一缺失不得开放端点, 不因个人凭据隔离通过而判定通过。
- [ ] **正常调用**: `pi mcp list` 发现正确项目端点；`agy_run_sync` 返回只读代码分析结果。使用摘要发起新的单轮请求成功, 显式续接被拒绝。
- [ ] **长任务**: `agy_run_sync` 返回 `running` 和 `job_id`, 同项目端点的 `agy_wait` / `agy_status` 能取得最终结果。记录所测 Pi 的有效请求超时 (默认 `60s` 与示例 `120s` 分开), 预算含冷启动与桥接, 不依赖进度通知续时。**PASS 判据**: `AGY_MCP_SYNC_WAIT_CAP` + agy 冷启动 + 桥接耗时 < 所测 Pi 的有效请求超时, 且超时前稳定返回 `running` 与可用 `job_id`。
- [ ] **磁盘与洪灌**: 向 worker 的 agy 配置路径 (每作业 tmpfs) 灌写至超限后写入失败且宿主机磁盘不增长；填充作业输出至 64 MiB 后被截断且有截断标记；将作业存储填至 `AGY_MCP_STATE_BUDGET` 以上后, GC 驱逐最老终态作业、在途作业不受影响。**PASS 判据**: 清理后宿主机侧作业存储占用低于 `AGY_MCP_STATE_BUDGET` 的 90%。
- [ ] **资源与回收**: 验证实际限额生效 (并发、HTTP 会话/在途/速率守卫), timeout / cancel / 服务重启能回收 worker 组; 服务重启后未完成作业必须标记为 `interrupted`, 不得报为成功 (`interrupted` 落在作业状态字段标记, 不新增 `failure_reason` 枚举; 若实现确需新枚举, 按契约变更同步常量注释、schema 与 README 三处）。

### E. 扩展阶段门禁
- [ ] **Phase 2 双项目**: 两个项目通过各自端点并行提交及查询作业；另一项目令牌、`cwd` / `dirs`、`job_id` 或幂等键均不能获得对方的作业、数据或操作权限。停掉一个实例, 另一个不受影响；Pi 不自动将请求移到别的项目。
- [ ] **Phase 3.3 会话续接前置门禁 (阻断项)**: 未完成 §3 T6 实测并补录 `MEASURED against agy 1.5.17` 证据之前, Phase 3.3 禁止进入实现与上线放行; 最终落地的续接路径 (A/B/C) 必须与 T6 实测结论严格一致, 任何情况下不得以持久化整个 `.gemini` 或共享跨作业刷新 token 换取续接能力。
- [ ] **Phase 3 项目内多轮**: 首轮成功签发句柄, 同项目、同快照且选定路径为 A/B 时第二轮复用上下文; 选定路径为 C 时第二轮不复用原生上下文, 由控制面摘要新开。并发续接串行, 同轮重试不重复运行。原生 ID、另一项目句柄、过期句柄及快照版本变化时明确拒绝。
- [ ] **会话续接与控制面重启恢复 (Phase 3.3 演练, 仅 managed-only 试点项目)**: 前置条件为 §3 T6 实测归档且选定路径 A/B/C。首轮作业写入唯一标记, 落盘目录须含 `meta.json`/`ownership.json`/`progress.json`/`result.json`, 作业结束后 worker tmpfs 销毁、staged 种子目录 mtime 与内容零变化; 重启控制面后句柄归属索引仍可读取; 按选定路径续接: 路径 A/B 须召回首轮标记且 worker 仍运行于每作业新鲜 tmpfs `.gemini`, 路径 C 须明确拒绝原生续接且不残留跨作业 `.gemini` 文件; 用不匹配的 `project_id` 或篡改 `ownership.json` 发起续接必须被拒绝且不启动 worker。**PASS 判据**: 全部步骤符合选定路径预期, staged 种子目录零改动, 跨项目续接 100% 被控制面拦截。
- [ ] **Phase 3 重启与回滚**: 同实例同快照重启后, 仍有效且选定路径为 A/B 的句柄可续接, 路径 C 下拒绝原生续接；换实例不可续接。回滚到 `disabled` 后拒绝续接, 同项目已完成作业仍可查询, 不加载旧会话缓存。

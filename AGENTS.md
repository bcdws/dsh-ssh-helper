# AGENTS.md

写给在这个仓库里改代码、或替用户安装这个插件的 AI agent。

## 安装 / 重装 DSH 插件

DSH 通过 `link:` 指向仓库目录，所以运行的就是这个目录里的代码。

1. 找到 dsh CLI。`dsh` 不在 PATH 时用 DSH 自带的 CLI 路径；找不到，或者不确定用哪个 profile，先问用户，不要猜。
2. 在仓库目录执行 `npm install`。
3. 执行 `dsh plugin --profile <profile> list`：
   - 已经有 `dsh-ssh-helper`，而且 link 指向本目录：重启 DSH（或重新加载插件）即可，不需要再 add。
   - 没有，或者指向别的目录：执行 `dsh plugin --profile <profile> add "link:<仓库绝对路径>"`。移除或更新旧条目的子命令以 `dsh plugin --help` 为准。
4. 验证：`list` 里能看到它，`ssh_hosts` 的结果里出现 `[policy]`。

约束：

- 不修改 `~/.ssh/config`，不添加主机。
- 不连接服务器，不执行远程命令。
- 已经装了插件的 DSH agent，不要再给它接 MCP 版本，否则工具会重复。
- 只报告安装结果和 profile 路径。

## MCP 版本

这是一个标准的 stdio MCP server，不绑定任何客户端或网关。客户端通过 `npx -y github:bcdws/dsh-ssh-helper#stable` 启动（见 README）。

发布流程是自动的，不要手动推 `stable`：

- 推送到 `main` → CI 全绿 → `promote` job 把 `stable` 快进到该提交。
- npx 每次启动都会重新解析分支，所以用户下次启动 server 时就拿到新代码；CI 失败的提交到不了 `stable`。
- 推 `v*` tag → 生成 release 并附上 tarball。发版时先改 `package.json` 的 `version`。

桌面客户端对**命令型** MCP 服务器的 `initialize` 有很短的预算（有的只有约 30 秒），超时就显示 “initialize 无响应”。所以这个包安装时必须快、且不能跑生命周期脚本：ssh2 已经预打包进 `vendor/ssh2.cjs`，运行时依赖为 0，npx 只解一个 tarball。不要把 ssh2 放回 `dependencies`。

## 结构与规则

```
lib/                     共享核心：连接池、策略、工具、面板 API（assistant-api.js）。不能引用 dsh/ 或 mcp/
index.js  dsh/  client.js   DSH 适配层
mcp/      bin/              MCP 适配层（stdio server、控制口 control.js、面板 panel.js + panel.html）
vendor/ssh2.cjs          预打包的 ssh2（构建产物，勿手改）
scripts/build-vendor.mjs 重新生成 vendor/ 的脚本
scripts/pack-smoke.mjs   打包冒烟：npm pack → 装 tarball → initialize
.github/workflows/ci.yml 测试、vendor 对比、打包冒烟、main→stable 快进、tag 发版
```

- 护栏必须留在工具内部：`ssh_run` 里的 `assertCommandAllowed`，以及文件写入用的 `assertWritePathAllowed`。适配层可以再加拦截，但不能替代这两处。
- 工具只读取中立的调用上下文 `{ callerId, signal }`（`lib/call-context.js`），由各适配层自己转换。
- MCP 进程的 stdout 只能输出协议消息，日志一律写 stderr。
- MCP server 进程从不写状态文件：默认只读跟随 `~/.dsh-ssh-mcp/state.json`，传了 `--state` 才改为跟随别的文件（比如 DSH 的）。这个文件唯一的写入方是 `dsh-ssh-mcp panel`，面板从不写 DSH 的 `state.json`。
- 面板 API 只有一份，就是 `lib/assistant-api.js`：DSH 挂在 `/ssh-pool`，MCP 面板挂在 `/api`，并打开 `checkHost`。新增一个面板功能时，两个面板都要考虑到。
- MCP 控制口（`mcp/control.js`）只提供状态读取和 open/close。它在 `initialize` 之后才启动，不能拖慢启动。测试里要用 `DSH_SSH_MCP_HOME` 指向临时目录，不要写到真实 home。
- 运行时依赖保持为 0：ssh2 用 `npm run build:vendor` 打包进 `vendor/ssh2.cjs`（它是 devDependency），`lib/pool.js` 通过 `require('../vendor/ssh2.cjs')` 加载。升级 ssh2 后必须重新构建；`test/mcp.test.mjs` 有打包检查，CI 也会重新构建并对比 `vendor/`，不一致就失败。不要引入 MCP SDK 之类的大依赖。
- 工具固定 8 个，名称和参数是两个适配层共同的契约，改动要同时考虑两边。
- 误报按 bug 处理：改 `lib/policy.js` 时，同时在 `test/safety.test.mjs` 补上拦截和放行的用例。
- prod 标记只做提醒，不拦截（这是用户的决定）。不要借 prod 加拦截规则，护栏仍然只有 `lib/policy.js` 这一份。
- 工具失败统一由 `lib/errors.js` 打上错误码。新增失败类型时，在 `FAILURE_CODES` 和 `RULES` 里一起加，并在 `test/failures.test.mjs` 补用例。错误提示里不能透露隐藏主机的存在。

## 测试

```bash
node test/run.mjs --offline
```

改完必须全部通过。测试里用的主机一律用 TEST-NET 地址（`192.0.2.x`）。`node test/run.mjs` 会跑 live 测试并连接真实主机，没有用户同意不要运行。

## 调用这些工具时

- 先调 `ssh_hosts` 看有哪些主机。
- 需要保留目录或环境变量时，给 `ssh_run` 传 `session`；慢操作给出 `expectedMs`；守护进程用 `background: true`，不要自己加 `&`。
- 读文件、搜内容优先用 `ssh_read` / `ssh_grep` / `ssh_glob`，小改动用 `ssh_edit`。
- 命令被护栏拒绝时，说明意图（哪台机器、做什么、预期影响），交给用户决定，不要换一种等价写法重试。
- 标了 `[PROD]` 的主机正在跑实际业务：优先只读检查；要重启、删除或修改配置和数据，先说明影响并取得用户确认。
- 失败时先看 `[error: <code>]` 那一行。客户端报了超时，命令可能已经执行了，先调 `ssh_hosts` 看 `lastFailure`，再决定要不要重试；不要改用本地 ssh。

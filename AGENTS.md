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
- 已经装了插件的 DSH agent，不要再在 Magpie 里给它开 MCP 版本，否则工具会重复。
- 只报告安装结果和 profile 路径。

## MCP 版本

由 Magpie 等客户端通过 `npx -y github:bcdws/dsh-ssh-helper` 安装（见 README），仓库里不需要做额外的事。npx 拉取的是 GitHub 默认分支，所以改动推送后才会到达 MCP 用户。

## 结构与规则

```
lib/                     共享核心：连接池、策略、工具。不能引用 dsh/ 或 mcp/
index.js  dsh/  client.js   DSH 适配层
mcp/      bin/              MCP 适配层（stdio）
```

- 护栏必须留在工具内部：`ssh_run` 里的 `assertCommandAllowed`，以及文件写入用的 `assertWritePathAllowed`。适配层可以再加拦截，但不能替代这两处。
- 工具只读取中立的调用上下文 `{ callerId, signal }`（`lib/call-context.js`），由各适配层自己转换。
- MCP 进程的 stdout 只能输出协议消息，日志一律写 stderr。
- MCP 只读取 DSH 的 `state.json`（而且只在传了 `--state` 时），从不写入。
- 运行时依赖只保留 `ssh2`，不要引入 MCP SDK 之类的大依赖。
- 工具固定 8 个，名称和参数是两个适配层共同的契约，改动要同时考虑两边。
- 误报按 bug 处理：改 `lib/policy.js` 时，同时在 `test/safety.test.mjs` 补上拦截和放行的用例。

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

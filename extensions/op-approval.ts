import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { DynamicBorder, type ExtensionAPI, type ExtensionContext, type ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { Container, Text } from "@earendil-works/pi-tui";

const HOME = process.env.USERPROFILE || process.env.HOME || ".";
const AUDIT_FILE = join(HOME, ".pi", "agent", "destructive-operation-guard.jsonl");
const SAFE_TOOLS = new Set(["read", "grep", "find", "ls", "update_plan", "pi_choices"]);
const PREVIEW_LIMIT = 1200;
const DETAIL_PAGE_SIZE = 18;

type Operation = {
	id: string;
	purpose: string;
	risk: string;
	severity: "warning" | "danger";
	display: string;
};

const operations = {
	fileDelete: (display: string): Operation => ({ id: "file-delete", severity: "danger", display, purpose: "Delete or clear local files or directories.", risk: "Deleted local data may be unrecoverable." }),
	fileOverwrite: (display: string): Operation => ({ id: "file-overwrite", severity: "warning", display, purpose: "Overwrite existing local file content.", risk: "The previous file content will be replaced." }),
	dockerStop: (display: string): Operation => ({ id: "docker-stop", severity: "warning", display, purpose: "Stop Docker containers or Compose services.", risk: "Running local containers and services will be interrupted." }),
	dockerDelete: (display: string): Operation => ({ id: "docker-delete", severity: "danger", display, purpose: "Delete Docker containers, images, volumes, networks, or cached resources.", risk: "Docker resources may be removed permanently; volume removal can destroy persistent data." }),
	processStop: (display: string): Operation => ({ id: "process-stop", severity: "warning", display, purpose: "Terminate one or more local processes.", risk: "Running work may be interrupted and unsaved data can be lost." }),
	serviceStop: (display: string): Operation => ({ id: "service-stop", severity: "warning", display, purpose: "Stop, disable, or remove a locally managed service.", risk: "The service will be interrupted; deleting it removes its local registration." }),
	gitDestructive: (display: string): Operation => ({ id: "git-destructive", severity: "danger", display, purpose: "Discard Git changes, clean untracked files, or force-delete a branch.", risk: "Uncommitted work or untracked files may be unrecoverable." }),
	databaseDestructive: (display: string): Operation => ({ id: "database-destructive", severity: "danger", display, purpose: "Delete or clear database data or schema objects.", risk: "Database records or schema objects may be permanently removed." }),
	orchestratorDelete: (display: string): Operation => ({ id: "orchestrator-delete", severity: "danger", display, purpose: "Delete infrastructure or orchestrated resources.", risk: "Running workloads or managed infrastructure resources may be removed." }),
	mcpDestructive: (display: string): Operation => ({ id: "mcp-destructive", severity: "danger", display, purpose: "Delete or destroy resources through an MCP server.", risk: "The remote resource may be permanently removed." }),
	uninstall: (display: string): Operation => ({ id: "uninstall", severity: "warning", display, purpose: "Uninstall a dependency or local software package.", risk: "Project dependencies or locally installed software will be removed." }),
	install: (display: string): Operation => ({ id: "install", severity: "warning", display, purpose: "Install software, dependencies, or a container image.", risk: "This downloads and installs code that can modify the project, system, services, or local disk usage." }),
};

function shellOperation(command: string): Operation | undefined {
	const c = command.toLowerCase();
	if (/\bdocker\s+(?:compose\s+)?(?:down|stop|kill)\b/.test(c)) return operations.dockerStop(command);
	if (/\bdocker\s+(?:(?:container|image|volume|network|system)\s+)?(?:rm|remove|prune)\b|\bdocker\s+compose\s+rm\b/.test(c)) return operations.dockerDelete(command);
	if (/\bdocker\s+(?:pull|build)\b|\bdocker\s+compose\s+(?:pull|build)\b|\bdocker\s+compose\s+up\b[^\n]*(?:--build|\s--build\b)/.test(c)) return operations.install(command);
	if (/\bgit\s+(?:clean\s+-[^\n]*(?:f|x)|reset\s+--hard|restore\b|checkout\s+--|branch\s+-d\b)/.test(c)) return operations.gitDestructive(command);
	if (/\b(?:kubectl\s+delete|helm\s+uninstall|terraform\s+destroy)\b/.test(c)) return operations.orchestratorDelete(command);
	if (/\b(?:drop\s+(?:database|schema|table|view|index)|truncate\s+(?:table\s+)?|delete\s+from)\b/.test(c)) return operations.databaseDestructive(command);
	if (/\b(?:npm\s+uninstall|pnpm\s+(?:remove|uninstall)|yarn\s+remove|pip(?:3)?\s+uninstall|uv\s+remove|poetry\s+remove|winget\s+uninstall|choco\s+uninstall|scoop\s+uninstall|brew\s+uninstall)\b/.test(c)) return operations.uninstall(command);
	if (/\b(?:npm\s+(?:install|i|ci|add)|pnpm\s+(?:install|i|add)|yarn\s+(?:install|add)|pip(?:3)?\s+install|uv\s+(?:add|sync|pip\s+install)|poetry\s+(?:add|install)|cargo\s+(?:install|add)|go\s+(?:install|get)|winget\s+install|choco\s+install|scoop\s+install|brew\s+install|apt(?:-get)?\s+install|dnf\s+install|pacman\s+-s)\b/.test(c)) return operations.install(command);
	if (/\b(?:taskkill|stop-process|tskill|killall|pkill|xkill|kill)\b/.test(c)) return operations.processStop(command);
	if (/\b(?:stop-service|restart-service|sc\s+(?:stop|delete)|net\s+stop|systemctl\s+(?:stop|disable)|service\s+\S+\s+stop|supervisorctl\s+stop|pm2\s+(?:stop|delete))\b/.test(c)) return operations.serviceStop(command);
	if (/\b(?:remove-item|clear-content|remove-itemproperty|del|erase|rmdir|rd|unlink|shred)\b|\brm\s+(?:-[^\n]*[rf]|--(?:recursive|force)|\S+)|\bfind\b[^\n]*(?:-delete|-exec\s+rm\b)|\btruncate\s+-s\s*0\b|\b(?:os\.(?:remove|unlink)|shutil\.rmtree|fs\.(?:rm|unlink)(?:sync)?)\s*\(/.test(c)) return operations.fileDelete(command);
	if (/(^|[;&|]\s*|\n\s*)[^\n]*?(?<![>\d])>(?!>)/.test(command) || /\b(?:set-content|out-file|sed\s+-i|perl\s+-pi)\b/.test(c)) return operations.fileOverwrite(command);
}

function redact(value: unknown, key = ""): unknown {
	if (/(token|secret|password|authorization|api[_-]?key|header|cookie)/i.test(key)) return "[redacted]";
	if (Array.isArray(value)) return value.map((item) => redact(item));
	if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([name, item]) => [name, redact(item, name)]));
	return value;
}

function actionValue(input: Record<string, unknown>): string {
	return ["action", "operation", "command"].map((key) => input[key]).filter((value): value is string => typeof value === "string").join(" ").toLowerCase();
}

function mcpOperation(toolName: string, input: Record<string, unknown>): Operation | undefined {
	const name = toolName.toLowerCase();
	const action = actionValue(input);
	const words = `${name} ${action}`;
	const display = `${toolName}\n${JSON.stringify(redact(input), null, 2)}`;
	if (/\b(?:kubectl[_-]?delete|terraform[_-]?destroy|destroy[_-]?(?:stack|deployment|resource)|delete[_-]?(?:stack|deployment|namespace))\b/.test(words)) return operations.orchestratorDelete(display);
	if (/\b(?:drop[_-]?(?:database|schema|table|view|index)|truncate[_-]?table|delete[_-]?(?:record|row|database))\b/.test(words)) return operations.databaseDestructive(display);
	if (/\b(?:stop|kill|terminate|shutdown)[_-]/.test(words) || /\b(?:stop|kill|terminate|shutdown)\b/.test(action)) return operations.processStop(display);
	if (/\b(?:uninstall|remove[_-]?(?:package|dependency))\b/.test(words)) return operations.uninstall(display);
	if (/\b(?:install|add[_-]?(?:package|dependency))\b/.test(words)) return operations.install(display);
	if (/\b(?:delete|remove|destroy|purge|prune|drop)[_-]/.test(words) || /\b(?:delete|remove|destroy|purge|prune|drop)\b/.test(action)) return operations.mcpDestructive(display);
}

export function detectProtectedOperation(event: ToolCallEvent, cwd: string): Operation | undefined {
	const input = event.input as Record<string, unknown>;
	if (SAFE_TOOLS.has(event.toolName)) return;
	if ((event.toolName === "bash" || event.toolName === "powershell") && typeof input.command === "string") return shellOperation(input.command);
	if (event.toolName === "write" && typeof input.path === "string") return existsSync(resolve(cwd, input.path)) ? operations.fileOverwrite(`write\n${input.path}`) : undefined;
	if (event.toolName === "edit" && typeof input.path === "string" && Array.isArray(input.edits)) {
		const clearsContent = input.edits.some((edit) => Boolean(edit) && typeof edit === "object" && typeof (edit as { oldText?: unknown }).oldText === "string" && (edit as { oldText: string }).oldText.length > 0 && typeof (edit as { newText?: unknown }).newText === "string" && (edit as { newText: string }).newText.trim().length === 0);
		return clearsContent ? operations.fileDelete(`edit\n${input.path}`) : undefined;
	}
	return mcpOperation(event.toolName, input);
}

type Approval = "once" | "session" | "deny";

function audit(operation: Operation, tool: string, approval: Approval | "session-allowed"): void {
	try {
		mkdirSync(dirname(AUDIT_FILE), { recursive: true });
		appendFileSync(AUDIT_FILE, `${JSON.stringify({ timestamp: new Date().toISOString(), operation: operation.id, tool, approval, approved: approval !== "deny" })}\n`, "utf8");
	} catch { /* Audit failures must not prevent the approval decision. */ }
}

async function confirmOperation(ctx: ExtensionContext, operation: Operation, tool: string): Promise<Approval> {
	const preview = operation.display.length > PREVIEW_LIMIT ? `${operation.display.slice(0, PREVIEW_LIMIT)}\n… ${operation.display.length - PREVIEW_LIMIT} characters omitted.` : operation.display;
	return ctx.ui.custom<Approval>((tui, theme, _kb, done) => {
		let viewDetails = false;
		let selected = 1;
		let page = 0;
		const container = new Container();
		const content = new Text("", 1, 0);
		container.addChild(new DynamicBorder((s) => theme.fg("accent", s)));
		container.addChild(content);
		container.addChild(new DynamicBorder((s) => theme.fg("accent", s)));
		const redraw = () => {
			if (viewDetails) {
				const lines = operation.display.split("\n");
				const totalPages = Math.max(1, Math.ceil(lines.length / DETAIL_PAGE_SIZE));
				page = Math.max(0, Math.min(page, totalPages - 1));
				content.setText([theme.fg("accent", theme.bold("Protected operation — full command")), "", ...lines.slice(page * DETAIL_PAGE_SIZE, (page + 1) * DETAIL_PAGE_SIZE), "", theme.fg("dim", `Page ${page + 1}/${totalPages}  |  ↑/↓ scroll  |  ←/→/Esc return`)].join("\n"));
				return;
			}
			const choices = ["View full command", "Allow once", `Always allow ${operation.id} this session`, "Deny"];
			content.setText([theme.fg(operation.severity === "danger" ? "error" : "warning", theme.bold(`${operation.severity === "danger" ? "⚠" : "!"} Protected operation`)), operation.purpose, "", theme.fg("dim", `Risk: ${operation.risk}`), "", theme.fg("dim", `Tool: ${tool}`), preview, "", ...choices.map((choice, index) => index === selected ? theme.fg(index === 3 ? "error" : "accent", `› ${choice}`) : `  ${choice}`), "", theme.fg("dim", "↑/↓ select  |  Enter confirm  |  Esc deny")].join("\n"));
		};
		redraw();
		return {
			render: (width) => container.render(width),
			invalidate: () => container.invalidate(),
			handleInput: (data) => {
				if (viewDetails) {
					if (data === "\x1b" || data === "\x1b[D" || data === "\x1b[C") viewDetails = false;
					else if (data === "\x1b[A" || data === "k") page--;
					else if (data === "\x1b[B" || data === "j") page++;
					redraw(); tui.requestRender(); return;
				}
				if (data === "\x1b") { done("deny"); return; }
				if (data === "\x1b[A" || data === "k") selected = (selected + 3) % 4;
				else if (data === "\x1b[B" || data === "j") selected = (selected + 1) % 4;
				else if (data === "\r" || data === "\n") {
					if (selected === 0) viewDetails = true;
					else done(selected === 1 ? "once" : selected === 2 ? "session" : "deny");
				}
				redraw(); tui.requestRender();
			},
		};
	});
}

export default function destructiveOperationGuard(pi: ExtensionAPI) {
	const sessionAllowed = new Set<string>();

	// This state lives only in the extension instance. A session start, including
	// resume and fork, deliberately receives no approvals from another session.
	pi.on("session_start", () => sessionAllowed.clear());
	pi.on("tool_call", async (event, ctx) => {
		const operation = detectProtectedOperation(event, ctx.cwd);
		if (!operation) return;
		if (sessionAllowed.has(operation.id)) {
			audit(operation, event.toolName, "session-allowed");
			return;
		}
		if (ctx.mode !== "tui" || !ctx.hasUI) return { block: true, reason: "Destructive Operation Guard requires an interactive approval dialog." };
		const approval = await confirmOperation(ctx, operation, event.toolName);
		audit(operation, event.toolName, approval);
		if (approval === "session") sessionAllowed.add(operation.id);
		if (approval === "deny") return { block: true, reason: `Blocked by Destructive Operation Guard: user denied ${operation.id}.` };
	});
}

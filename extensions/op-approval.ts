import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";

const HOME = process.env.USERPROFILE || process.env.HOME || ".";
const AUDIT_FILE = join(HOME, ".pi", "agent", "destructive-operation-guard.jsonl");

type Operation = {
	id: string;
	purpose: string;
	risk: string;
	severity: "warning" | "danger";
	display: string;
};

const operations = {
	fileDelete: (display: string): Operation => ({
		id: "file-delete", severity: "danger", display,
		purpose: "Delete or clear local files or directories.",
		risk: "Deleted local data may be unrecoverable.",
	}),
	fileOverwrite: (display: string): Operation => ({
		id: "file-overwrite", severity: "warning", display,
		purpose: "Overwrite existing local file content.",
		risk: "The previous file content will be replaced.",
	}),
	dockerStop: (display: string): Operation => ({
		id: "docker-stop", severity: "warning", display,
		purpose: "Stop Docker containers or Compose services.",
		risk: "Running local containers and services will be interrupted.",
	}),
	dockerDelete: (display: string): Operation => ({
		id: "docker-delete", severity: "danger", display,
		purpose: "Delete Docker containers, images, volumes, networks, or cached resources.",
		risk: "Docker resources may be removed permanently; volume removal can destroy persistent data.",
	}),
	processStop: (display: string): Operation => ({
		id: "process-stop", severity: "warning", display,
		purpose: "Terminate one or more local processes.",
		risk: "Running work may be interrupted and unsaved data can be lost.",
	}),
	serviceStop: (display: string): Operation => ({
		id: "service-stop", severity: "warning", display,
		purpose: "Stop, disable, or remove a locally managed service.",
		risk: "The service will be interrupted; deleting it removes its local registration.",
	}),
	gitDestructive: (display: string): Operation => ({
		id: "git-destructive", severity: "danger", display,
		purpose: "Discard Git changes, clean untracked files, or force-delete a branch.",
		risk: "Uncommitted work or untracked files may be unrecoverable.",
	}),
	databaseDestructive: (display: string): Operation => ({
		id: "database-destructive", severity: "danger", display,
		purpose: "Delete or clear database data or schema objects.",
		risk: "Database records or schema objects may be permanently removed.",
	}),
	orchestratorDelete: (display: string): Operation => ({
		id: "orchestrator-delete", severity: "danger", display,
		purpose: "Delete infrastructure or orchestrated resources.",
		risk: "Running workloads or managed infrastructure resources may be removed.",
	}),
	uninstall: (display: string): Operation => ({
		id: "uninstall", severity: "warning", display,
		purpose: "Uninstall a dependency or local software package.",
		risk: "Project dependencies or locally installed software will be removed.",
	}),
	install: (display: string): Operation => ({
		id: "install", severity: "warning", display,
		purpose: "Install software, dependencies, or a container image.",
		risk: "This downloads and installs code that can modify the project, system, services, or local disk usage.",
	}),
};

function shellOperation(command: string): Operation | undefined {
	const c = command.toLowerCase();
	const display = command;
	// Docker must precede generic process and delete rules.
	if (/\bdocker\s+(?:compose\s+)?(?:down|stop|kill)\b/.test(c)) return operations.dockerStop(display);
	if (/\bdocker\s+(?:(?:container|image|volume|network|system)\s+)?(?:rm|remove|prune)\b|\bdocker\s+compose\s+rm\b/.test(c)) return operations.dockerDelete(display);
	if (/\bdocker\s+(?:pull|build)\b|\bdocker\s+compose\s+(?:pull|build)\b|\bdocker\s+compose\s+up\b[^\n]*(?:--build|\s--build\b)/.test(c)) return operations.install(display);

	if (/\bgit\s+(?:clean\s+-[^\n]*(?:f|x)|reset\s+--hard|restore\b|checkout\s+--|branch\s+-d\b)/.test(c)) return operations.gitDestructive(display);
	if (/\b(?:kubectl\s+delete|helm\s+uninstall|terraform\s+destroy)\b/.test(c)) return operations.orchestratorDelete(display);
	if (/\b(?:drop\s+(?:database|schema|table|view|index)|truncate\s+(?:table\s+)?|delete\s+from)\b/.test(c)) return operations.databaseDestructive(display);

	if (/\b(?:npm\s+uninstall|pnpm\s+(?:remove|uninstall)|yarn\s+remove|pip(?:3)?\s+uninstall|uv\s+remove|poetry\s+remove|winget\s+uninstall|choco\s+uninstall|scoop\s+uninstall|brew\s+uninstall)\b/.test(c)) return operations.uninstall(display);
	if (/\b(?:npm\s+(?:install|i|ci|add)|pnpm\s+(?:install|i|add)|yarn\s+(?:install|add)|pip(?:3)?\s+install|uv\s+(?:add|sync|pip\s+install)|poetry\s+(?:add|install)|cargo\s+(?:install|add)|go\s+(?:install|get)|winget\s+install|choco\s+install|scoop\s+install|brew\s+install|apt(?:-get)?\s+install|dnf\s+install|pacman\s+-s)\b/.test(c)) return operations.install(display);

	if (/\b(?:taskkill|stop-process|tskill|killall|pkill|xkill|kill)\b/.test(c)) return operations.processStop(display);
	if (/\b(?:stop-service|restart-service|sc\s+(?:stop|delete)|net\s+stop|systemctl\s+(?:stop|disable)|service\s+\S+\s+stop|supervisorctl\s+stop|pm2\s+(?:stop|delete))\b/.test(c)) return operations.serviceStop(display);

	if (/\b(?:remove-item|clear-content|remove-itemproperty|del|erase|rmdir|rd|unlink|shred)\b|\brm\s+(?:-[^\n]*[rf]|--(?:recursive|force)|\S+)|\bfind\b[^\n]*(?:-delete|-exec\s+rm\b)|\btruncate\s+-s\s*0\b|\b(?:os\.(?:remove|unlink)|shutil\.rmtree|fs\.(?:rm|unlink)(?:sync)?)\s*\(/.test(c)) return operations.fileDelete(display);
	// Avoid append (>>) and stderr redirects (2>); capture ordinary output replacement only.
	if (/(^|[;&|]\s*|\n\s*)[^\n]*?(?<![>\d])>(?!>)/.test(command) || /\b(?:set-content|out-file)\b/.test(c)) return operations.fileOverwrite(display);
	if (/\b(?:sed\s+-i|perl\s+-pi)\b/.test(c)) return operations.fileOverwrite(display);
	return undefined;
}

function redact(value: unknown, key = ""): unknown {
	if (/(token|secret|password|authorization|api[_-]?key|header|cookie)/i.test(key)) return "[redacted]";
	if (Array.isArray(value)) return value.map((item) => redact(item));
	if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, redact(v, k)]));
	return value;
}

function mcpOperation(toolName: string, input: Record<string, unknown>): Operation | undefined {
	const text = `${toolName} ${JSON.stringify(input)}`.toLowerCase();
	const display = `${toolName}\n${JSON.stringify(redact(input), null, 2)}`;
	if (/\b(?:delete|remove|destroy|purge|prune|drop)\b/.test(text)) return operations.fileDelete(display);
	if (/\b(?:stop|kill|terminate|shutdown)\b/.test(text)) return operations.processStop(display);
	if (/\buninstall\b/.test(text)) return operations.uninstall(display);
	if (/\binstall\b/.test(text)) return operations.install(display);
	return undefined;
}

export function detectProtectedOperation(event: ToolCallEvent, cwd: string): Operation | undefined {
	const input = event.input as Record<string, unknown>;
	if ((event.toolName === "bash" || event.toolName === "powershell") && typeof input.command === "string") return shellOperation(input.command);
	if (event.toolName === "write" && typeof input.path === "string") {
		const path = resolve(cwd, input.path);
		return existsSync(path) ? operations.fileOverwrite(`write\n${input.path}`) : undefined;
	}
	if (event.toolName === "edit" && typeof input.path === "string" && Array.isArray(input.edits)) {
		const removesContent = input.edits.some((edit) => Boolean(edit) && typeof edit === "object" && typeof (edit as { oldText?: unknown }).oldText === "string" && (edit as { oldText: string }).oldText.length > 0 && (edit as { newText?: unknown }).newText === "");
		return removesContent ? operations.fileDelete(`edit\n${input.path}`) : undefined;
	}
	if (["read", "grep", "find", "ls"].includes(event.toolName)) return undefined;
	return mcpOperation(event.toolName, input);
}

function audit(operation: Operation, tool: string, approved: boolean): void {
	try {
		mkdirSync(dirname(AUDIT_FILE), { recursive: true });
		appendFileSync(AUDIT_FILE, `${JSON.stringify({ timestamp: new Date().toISOString(), operation: operation.id, tool, approved })}\n`, "utf8");
	} catch { /* Audit failures must not prevent the approval decision. */ }
}

export default function destructiveOperationGuard(pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx: ExtensionContext) => {
		const operation = detectProtectedOperation(event, ctx.cwd);
		if (!operation) return;
		if (ctx.mode !== "tui" || !ctx.hasUI) return { block: true, reason: "Destructive Operation Guard requires an interactive approval dialog." };
		const approved = await ctx.ui.confirm(
			`${operation.severity === "danger" ? "⚠" : "!"} Protected operation: ${operation.purpose}`,
			`Risk: ${operation.risk}\n\nProposed ${event.toolName} operation:\n${operation.display}\n\nAllow this operation once?`,
		);
		audit(operation, event.toolName, approved);
		if (!approved) return { block: true, reason: `Blocked by Destructive Operation Guard: user denied ${operation.id}.` };
	});
}

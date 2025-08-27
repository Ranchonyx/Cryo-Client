import type {DebugLoggerFunction} from "node:util";

export function CreateDebugLogger(section: string): DebugLoggerFunction {
    if (!process.env.DEBUG?.includes(section))
        return () => {
        };

    return (msg: string, ...params: unknown[]) => {
        const err = new Error();
        const stack = err.stack?.split("\n");
        const caller_line = stack?.[2] ?? "unknown";
        const method_cleaned = caller_line.trim().replace(/^at\s+/, "");
        const method = method_cleaned.substring(0, method_cleaned.indexOf("(") - 1);
        const position = method_cleaned.substring(method_cleaned.lastIndexOf(":") - 2, method_cleaned.length - 1);

        console.info(`PID: ${process.pid.toString().padEnd(8, " ")} ${section.padEnd(24, " ")}${new Date().toISOString().padEnd(32, " ")} ${method.padEnd(64, " ")} ${position.padEnd(8, " ")} ${msg}`, ...params)
    }
}
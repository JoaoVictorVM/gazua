/** Tools wrapped in this process, so the runner can describe them by name. */

export type ToolFunction = (...args: never[]) => unknown;

export interface RegisteredTool {
  readonly name: string;
  readonly original: ToolFunction;
  readonly proxy: ToolFunction;
  readonly isAsync: boolean;
  readonly argumentStyle: "none" | "object";
}

const tools = new Map<string, RegisteredTool[]>();
const proxies = new WeakMap<ToolFunction, Map<string, ToolFunction>>();

export function cachedProxy(name: string, original: ToolFunction): ToolFunction | undefined {
  return proxies.get(original)?.get(name);
}

export function register(entry: RegisteredTool): void {
  let byName = proxies.get(entry.original);
  if (byName === undefined) {
    byName = new Map();
    proxies.set(entry.original, byName);
  }
  byName.set(entry.name, entry.proxy);
  const entries = tools.get(entry.name) ?? [];
  if (!entries.some((item) => item.original === entry.original)) {
    entries.push(entry);
  }
  tools.set(entry.name, entries);
}

/** Every registered name. More than one function under a name is a conflict. */
export function snapshot(): ReadonlyMap<string, readonly RegisteredTool[]> {
  return new Map([...tools].map(([name, entries]) => [name, [...entries]]));
}

export function clearRegistry(): void {
  tools.clear();
}

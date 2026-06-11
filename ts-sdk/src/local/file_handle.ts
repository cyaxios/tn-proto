export interface TnFileHandle {
  text(): Promise<string>;
  slice(start: number, end?: number): Promise<string>;
  size(): Promise<number>;
  readonly name: string;
}

/** Minimal structural subset of FileSystemFileHandle that this module uses.
 * Keeps the tsconfig Node-only (no lib:dom) while remaining compatible with
 * any real FileSystemFileHandle passed from browser code. */
interface FsaHandle {
  readonly name: string;
  getFile(): Promise<{
    readonly size: number;
    text(): Promise<string>;
    slice(start?: number, end?: number): { text(): Promise<string> };
  }>;
}

export function fromFileSystemHandle(h: FsaHandle): TnFileHandle {
  return {
    name: h.name,
    async text() { return (await h.getFile()).text(); },
    async slice(start, end) { return (await h.getFile()).slice(start, end).text(); },
    async size() { return (await h.getFile()).size; },
  };
}

/** Build a TnFileHandle from a static string — for tests only. */
export function fromText(content: string, name = "test.tn.log"): TnFileHandle {
  const bytes = new TextEncoder().encode(content);
  return {
    name,
    async text() { return content; },
    async slice(start, end) { return new TextDecoder().decode(bytes.slice(start, end)); },
    async size() { return bytes.length; },
  };
}

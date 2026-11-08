// Format-independent analysis: entropy, strings, hashes, API flags.

export function entropy(bytes, start = 0, end = bytes.length) {
  const n = end - start;
  if (n <= 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = start; i < end; i++) counts[bytes[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i]) {
      const p = counts[i] / n;
      h -= p * Math.log2(p);
    }
  }
  return h;
}

export function entropyBlocks(bytes, maxBlocks = 1024) {
  const size = bytes.length;
  if (!size) return { blockSize: 0, values: [] };
  const blockSize = Math.max(256, Math.ceil(size / maxBlocks));
  const values = [];
  for (let off = 0; off < size; off += blockSize) {
    values.push(entropy(bytes, off, Math.min(size, off + blockSize)));
  }
  return { blockSize, values };
}

const isPrintable = (b) => (b >= 0x20 && b < 0x7f) || b === 0x09;
const MAX_TEXT = 400;

function decodeAscii(bytes, start, end) {
  const stop = Math.min(end, start + MAX_TEXT);
  let s = '';
  for (let i = start; i < stop; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

function decodeUtf16(bytes, start, end) {
  const stop = Math.min(end, start + MAX_TEXT * 2);
  let s = '';
  for (let i = start; i < stop; i += 2) s += String.fromCharCode(bytes[i]);
  return s;
}

const CATEGORIES = [
  ['url', /\b(?:https?|ftp):\/\/[^\s"'<>]+/i],
  ['ip', /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/],
  ['registry', /\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\b|SOFTWARE\\(?:Microsoft|Classes|Wow6432Node)/i],
  ['path', /[a-z]:\\[^\s]|\\\\[\w.$-]+\\|(?:^|\s)\/(?:usr|etc|tmp|bin|home|var|proc|dev)\//i],
  ['module', /\b[\w-]+\.(?:dll|exe|sys|so(?:\.\d+)*|dylib)\b/i],
];

export function categorize(text) {
  for (const [name, re] of CATEGORIES) if (re.test(text)) return name;
  return '';
}

export function extractStrings(bytes, minLen = 5, maxCount = 250000) {
  const out = [];
  const n = bytes.length;

  let start = -1;
  for (let i = 0; i <= n; i++) {
    if (i < n && isPrintable(bytes[i])) {
      if (start < 0) start = i;
    } else {
      if (start >= 0 && i - start >= minLen) {
        out.push({ off: start, len: i - start, enc: 'ASCII', text: decodeAscii(bytes, start, i) });
        if (out.length >= maxCount) break;
      }
      start = -1;
    }
  }

  let i = 0;
  let wide = 0;
  while (i + 1 < n && wide < maxCount) {
    if (isPrintable(bytes[i]) && bytes[i + 1] === 0) {
      let j = i;
      while (j + 1 < n && isPrintable(bytes[j]) && bytes[j + 1] === 0) j += 2;
      const chars = (j - i) / 2;
      if (chars >= minLen) {
        out.push({ off: i, len: j - i, enc: 'UTF-16', text: decodeUtf16(bytes, i, j) });
        wide++;
      }
      i = j;
    } else {
      i++;
    }
  }

  out.sort((a, b) => a.off - b.off);
  for (const s of out) s.cat = categorize(s.text);
  return out;
}

export async function hashes(bytes) {
  if (!crypto?.subtle) return {};
  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const [sha1, sha256] = await Promise.all([
    crypto.subtle.digest('SHA-1', bytes),
    crypto.subtle.digest('SHA-256', bytes),
  ]);
  return { 'SHA-256': hex(sha256), 'SHA-1': hex(sha1) };
}

// API names that are worth a second look. These are hints, not verdicts:
// plenty of legitimate software uses every one of them.
const API_FLAGS = [
  ['injection', /^(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread(Ex)?|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC|NtQueueApcThread|SetThreadContext|NtUnmapViewOfSection|ZwUnmapViewOfSection|NtWriteVirtualMemory)$/],
  ['anti-debug', /^(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString[AW]?|NtSetInformationThread|ptrace)$/],
  ['keyboard', /^(SetWindowsHookEx[AW]?|GetAsyncKeyState|GetKeyboardState|RegisterRawInputDevices)$/],
  ['network', /^(URLDownloadToFile[AW]?|InternetOpen(Url)?[AW]?|InternetReadFile|HttpSendRequest[AW]?|HttpOpenRequest[AW]?|WinHttp(Open|Connect|SendRequest|ReadData)|WSAStartup|connect|socket|send|recv|getaddrinfo|gethostbyname)$/],
  ['crypto', /^(Crypt(Encrypt|Decrypt|AcquireContext[AW]?|GenKey|ImportKey)|BCrypt(Encrypt|Decrypt|GenerateSymmetricKey|OpenAlgorithmProvider))$/],
  ['persistence', /^(RegSetValueEx[AW]?|RegCreateKeyEx[AW]?|CreateService[AW]?|ChangeServiceConfig[AW]?)$/],
  ['execution', /^(CreateProcess[AW]?|CreateProcessAsUser[AW]?|ShellExecute(Ex)?[AW]?|WinExec|system|execve|execl|execvp|popen|fork)$/],
  ['memory', /^(VirtualAlloc|VirtualProtect(Ex)?|NtAllocateVirtualMemory|NtProtectVirtualMemory|mprotect|mmap)$/],
  ['dynamic-load', /^(LoadLibrary(Ex)?[AW]?|GetProcAddress|LdrLoadDll|LdrGetProcedureAddress|dlopen|dlsym)$/],
];

export function flagApi(name) {
  if (!name) return '';
  for (const [cat, re] of API_FLAGS) if (re.test(name)) return cat;
  return '';
}

// What a file can do, in plain words, mapped to MITRE ATT&CK techniques.
//
// Each rule lists groups of evidence; a rule fires when every group has at
// least one hit. Evidence comes from imported functions, strings, .NET member
// references, Android permissions and DEX method references. This is static
// evidence of capability, not proof the code path runs.

const A = (re) => ({ k: 'api', re });   // native import (PE, ELF, Mach-O)
const S = (re) => ({ k: 'str', re });   // string in the file
const N = (re) => ({ k: 'net', re });   // .NET member reference (Type::Member)
const P = (re) => ({ k: 'perm', re });  // Android permission
const D = (re) => ({ k: 'dex', re });   // DEX method reference (Lpkg/Class;->method)

// weak: common in ordinary software too, shown apart from the rest
const R = (name, attack, tactic, groups, os = '', weak = false) => ({ name, attack, tactic, groups, os, weak });

const RULES = [
  // ---- Collection
  R('Log keystrokes', 'T1056.001', 'Collection', [[A(/^GetAsyncKeyState$/), A(/^SetWindowsHookEx[AW]?$/), A(/^GetKeyboardState$/), A(/^RegisterRawInputDevices$/), N(/::(GetAsyncKeyState|SetWindowsHookEx)$/)]]),
  R('Take screenshots', 'T1113', 'Collection', [[A(/^BitBlt$/), A(/^PrintWindow$/), N(/Graphics::CopyFromScreen$/), A(/^CGWindowListCreateImage$/), A(/^CGDisplayCreateImage$/)], [A(/^(GetDC|GetWindowDC|CreateCompatibleBitmap|CreateDCW?A?)$/), N(/Graphics::CopyFromScreen$/), A(/^CG(WindowList|Display)CreateImage$/)]]),
  R('Read the clipboard', 'T1115', 'Collection', [[A(/^GetClipboardData$/), N(/Clipboard::Get(Text|Data)$/), D(/ClipboardManager;->getPrimaryClip/)]]),
  R('Record audio', 'T1123', 'Collection', [[A(/^waveInOpen$/), A(/^mciSendString[AW]?$/), S(/^AVCaptureDevice$/)]]),
  R('Use the webcam', 'T1125', 'Collection', [[A(/^capCreateCaptureWindow[AW]?$/), S(/^AVCaptureDevice$/)]], 'win'),
  // ---- Credential access
  R('Read saved browser passwords', 'T1555.003', 'Credential Access', [[S(/Login Data|Local State|logins\.json|key4\.db|Web Data/)], [S(/Chrome|Chromium|Edge|Firefox|Opera|Brave/i)]]),
  R('Decrypt data protected by Windows (DPAPI)', 'T1555', 'Credential Access', [[A(/^CryptUnprotectData$/), N(/ProtectedData::Unprotect$/)]]),
  R('Read the macOS keychain', 'T1555.001', 'Credential Access', [[A(/^SecKeychain(FindGenericPassword|FindInternetPassword|ItemCopyContent)$/), A(/^SecItemCopyMatching$/)]]),
  R('Read the Linux password files', 'T1003.008', 'Credential Access', [[S(/^\/etc\/(shadow|passwd)$/)]]),
  // ---- Persistence
  R('Start itself when Windows starts (Run key)', 'T1547.001', 'Persistence', [[A(/^RegSetValueEx[AW]?$/), A(/^RegCreateKeyEx[AW]?$/), N(/RegistryKey::SetValue$/), S(/^reg(\.exe)? add/i)], [S(/CurrentVersion\\Run(Once)?\b/i)]]),
  R('Copy itself to the Startup folder', 'T1547.001', 'Persistence', [[S(/\\Start Menu\\Programs\\Startup|shell:startup/i)]]),
  R('Install a Windows service', 'T1543.003', 'Persistence', [[A(/^CreateService[AW]?$/), S(/^sc(\.exe)? create /i)]]),
  R('Create a scheduled task', 'T1053.005', 'Persistence', [[S(/schtasks(\.exe)?\s+\/create/i), S(/^schtasks(\.exe)?$/i)]]),
  R('Add a cron job', 'T1053.003', 'Persistence', [[S(/crontab|\/etc\/cron\.|\/var\/spool\/cron/)]]),
  R('Install a systemd service', 'T1543.002', 'Persistence', [[S(/\/etc\/systemd\/system|systemctl enable|\.service$/)]]),
  R('Install a macOS launch agent or daemon', 'T1543.001', 'Persistence', [[S(/Library\/Launch(Agents|Daemons)/)]]),
  R('Preload a library into every Linux program', 'T1574.006', 'Persistence', [[S(/\/etc\/ld\.so\.preload|LD_PRELOAD/)]]),
  // ---- Privilege escalation / defense evasion
  R('Inject code into another process', 'T1055', 'Defense Evasion', [[A(/^(VirtualAllocEx|NtAllocateVirtualMemory|ZwAllocateVirtualMemory)$/)], [A(/^(WriteProcessMemory|NtWriteVirtualMemory|ZwWriteVirtualMemory)$/)], [A(/^(CreateRemoteThread(Ex)?|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC|NtQueueApcThread|SetThreadContext)$/)]]),
  R('Hollow out another process and run code in it', 'T1055.012', 'Defense Evasion', [[A(/^CreateProcess(Internal)?[AW]?$/)], [A(/^(NtUnmapViewOfSection|ZwUnmapViewOfSection)$/)], [A(/^(SetThreadContext|Wow64SetThreadContext|NtSetContextThread)$/), A(/^(ResumeThread|NtResumeThread)$/)]]),
  R('Detect a debugger', 'T1622', 'Defense Evasion', [[A(/^(IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString[AW]?)$/), A(/^(NtQueryInformationProcess|ZwQueryInformationProcess)$/), N(/Debugger::(get_)?IsAttached$/), S(/^\/proc\/self\/status$/), S(/TracerPid/)]], '', true),
  R('Block debuggers with ptrace', 'T1622', 'Defense Evasion', [[A(/^ptrace$/)]], 'nix'),
  R('Detect virtual machines or sandboxes', 'T1497', 'Defense Evasion', [[S(/VBoxService|VBoxTray|vboxguest|vmtoolsd|VMware Tools|SbieDll|QEMU|Xen ?Tools|wine_get_unix_file_name|VIRTUAL_BOX/i)]]),
  R('Resolve functions at runtime to hide imports', 'T1027.007', 'Defense Evasion', [[A(/^GetProcAddress$/), A(/^dlsym$/)], [A(/^(LoadLibrary(Ex)?[AW]?|LdrLoadDll)$/), A(/^dlopen$/)]], '', true),
  R('Load code in memory from bytes', 'T1620', 'Defense Evasion', [[N(/Assembly::Load(File|From)?$/), N(/AppDomain::Load$/), D(/(DexClassLoader|InMemoryDexClassLoader|PathClassLoader);-><init>/)]]),
  R('Decode Base64 data', 'T1140', 'Defense Evasion', [[N(/Convert::FromBase64String$/), A(/^CryptStringToBinary[AW]?$/), D(/Base64;->decode/)]]),
  R('Adjust its own privileges', 'T1134', 'Privilege Escalation', [[A(/^AdjustTokenPrivileges$/)], [A(/^LookupPrivilegeValue[AW]?$/), S(/^Se(Debug|Shutdown|TakeOwnership|LoadDriver)Privilege$/)]]),
  R('Try to bypass User Account Control', 'T1548.002', 'Privilege Escalation', [[S(/fodhelper|eventvwr\.exe|sdclt\.exe|computerdefaults\.exe|ms-settings\\shell\\open\\command|mscfile\\shell\\open\\command/i)]]),
  R('Delete itself or clean up traces', 'T1070.004', 'Defense Evasion', [[S(/&\s*del\s|del \/f \/q|cmd(\.exe)? \/c del |choice \/c y \/n .*del /i)]]),
  R('Turn off Windows Defender or the firewall', 'T1562.001', 'Defense Evasion', [[S(/DisableAntiSpyware|DisableRealtimeMonitoring|Set-MpPreference|netsh (adv)?firewall .*(off|disable)/i)]]),
  R('Delete shadow copies (blocks file recovery)', 'T1490', 'Impact', [[S(/vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no|wbadmin\s+delete/i)]]),
  // ---- Execution
  R('Run other programs', 'T1106', 'Execution', [[A(/^(CreateProcess[AW]?|WinExec|ShellExecute(Ex)?[AW]?|CreateProcessAsUser[AW]?)$/), A(/^(execve|execv|execvp|posix_spawnp?|system|popen)$/), N(/Process::Start$/), D(/Runtime;->exec/)]]),
  R('Run Windows command-line commands', 'T1059.003', 'Execution', [[S(/^cmd(\.exe)?( \/[ckq])?$|cmd(\.exe)? \/[ck] /i)]]),
  R('Run PowerShell', 'T1059.001', 'Execution', [[S(/powershell(\.exe)?|pwsh(\.exe)?|-EncodedCommand|-enc\s+[A-Za-z0-9+/=]{20,}/i)]]),
  R('Run shell commands', 'T1059.004', 'Execution', [[S(/^\/bin\/(ba|z|da)?sh$|^sh -c|^\/bin\/sh -c/)], [A(/^(execve|execv|execl|execlp|system|popen|fork|posix_spawn)$/), D(/Runtime;->exec/)]]),
  R('Run AppleScript', 'T1059.002', 'Execution', [[S(/osascript|NSAppleScript/)]]),
  // ---- Discovery
  R('List running processes', 'T1057', 'Discovery', [[A(/^(CreateToolhelp32Snapshot|EnumProcesses|NtQuerySystemInformation)$/), N(/Process::GetProcess(es|esByName)$/), S(/^\/proc\/%d|^\/proc\/\d*\/?cmdline$/)], [A(/^(Process32First[W]?|Process32Next[W]?|EnumProcesses|NtQuerySystemInformation)$/), N(/Process::GetProcess(es|esByName)$/), S(/cmdline/)]]),
  R('Collect system information', 'T1082', 'Discovery', [[A(/^(GetComputerName(Ex)?[AW]?|GetVersionEx[AW]?|RtlGetVersion|GetSystemInfo|GetNativeSystemInfo|uname|sysctlbyname)$/), N(/Environment::get_(MachineName|OSVersion|UserName)$/), D(/Build;->|TelephonyManager;->getDeviceId/)]], '', true),
  R('Search for files', 'T1083', 'Discovery', [[A(/^FindFirstFile(Ex)?[AW]?$/), A(/^(opendir|readdir|fts_open|nftw)$/), N(/Directory::(GetFiles|EnumerateFiles|GetDirectories)$/)], [A(/^FindNextFile[AW]?$/), A(/^(readdir|fts_read|nftw)$/), N(/Directory::(GetFiles|EnumerateFiles|GetDirectories)$/)]], '', true),
  R('Check the public IP or location', 'T1016', 'Discovery', [[S(/api\.ipify\.org|ipinfo\.io|ip-api\.com|checkip\.|icanhazip|ifconfig\.me|wtfismyip/i)]]),
  // ---- Command and control / exfiltration
  R('Download files from the internet', 'T1105', 'Command and Control', [[A(/^URLDownloadToFile[AW]?$/), A(/^(InternetOpenUrl[AW]?|InternetReadFile|HttpOpenRequest[AW]?)$/), A(/^(WinHttpOpen|WinHttpReceiveResponse|WinHttpReadData)$/), N(/WebClient::Download(String|File|Data)(Async)?$/), N(/HttpClient::(GetAsync|GetByteArrayAsync|GetStringAsync)$/), A(/^curl_easy_perform$/), D(/(HttpURLConnection|OkHttpClient|URL);->(openConnection|newCall)/)]]),
  R('Talk to a web server', 'T1071.001', 'Command and Control', [[A(/^(InternetConnect[AW]?|InternetOpenUrl[AW]?|HttpSendRequest[AW]?|WinHttpConnect|WinHttpSendRequest)$/), N(/(WebClient|HttpClient|WebRequest|HttpWebRequest)::/), A(/^curl_easy_(setopt|perform)$/), A(/^(NSURLSession|CFHTTPMessageCreateRequest)$/), D(/HttpURLConnection;->|OkHttpClient;->/)], [S(/^https?:\/\/[^\s"']{4,}/)]]),
  R('Open raw network connections', 'T1095', 'Command and Control', [[A(/^(connect|WSAConnect|WSASocket[AW]?|socket)$/), N(/(TcpClient|Socket)::(Connect|ConnectAsync|\.ctor)$/), D(/Ljava\/net\/Socket;-><init>/)], [A(/^(send|recv|WSASend|WSARecv|sendto|recvfrom|write|read)$/), N(/(NetworkStream|Socket)::(Write|Read|Send|Receive)/), D(/Socket;->get(Input|Output)Stream/)]]),
  R('Send data through Telegram or Discord', 'T1567', 'Exfiltration', [[S(/api\.telegram\.org\/bot|discord(app)?\.com\/api\/webhooks/i)]]),
  R('Use Tor or onion addresses', 'T1090.003', 'Command and Control', [[S(/\.onion\b|tor2web|\btorrc\b/i)]]),
  // ---- Impact
  R('Encrypt files', 'T1486', 'Impact', [[A(/^(CryptEncrypt|BCryptEncrypt|EVP_EncryptUpdate|CCCrypt)$/), N(/(CryptoStream|RijndaelManaged|AesManaged|Aes)::(\.ctor|Create|CreateEncryptor)$/)], [A(/^FindFirstFile(Ex)?[AW]?$/), A(/^(opendir|readdir|nftw)$/), N(/Directory::(GetFiles|EnumerateFiles)$/)]]),
  R('Show a ransom note or wallet address', 'T1486', 'Impact', [[S(/your (files|documents|data) (have been|are) encrypted|bitcoin address|decrypt(ion)? (key|tool)|\.onion/i)], [S(/bitcoin|BTC|monero|XMR|wallet|ransom/i)]]),
  R('Mine cryptocurrency', 'T1496', 'Impact', [[S(/stratum\+tcp:\/\/|xmrig|cryptonight|randomx|minexmr|nanopool/i)]]),
  R('Shut down or restart the computer', 'T1529', 'Impact', [[A(/^(ExitWindowsEx|InitiateSystemShutdown(Ex)?[AW]?|NtShutdownSystem)$/), S(/shutdown(\.exe)?\s+\/[sr]/i)]]),
  // ---- Android (Mobile ATT&CK)
  R('Read or send SMS messages', 'T1636.004', 'Collection', [[P(/\.(READ_SMS|RECEIVE_SMS|SEND_SMS)$/), D(/SmsManager;->send(Text|Multipart)Message/)]]),
  R('Read contacts', 'T1636.003', 'Collection', [[P(/\.READ_CONTACTS$/)]]),
  R('Read the call log', 'T1636.002', 'Collection', [[P(/\.READ_CALL_LOG$/)]]),
  R('Track the phone location', 'T1430', 'Collection', [[P(/\.ACCESS_(FINE|COARSE|BACKGROUND)_LOCATION$/)]]),
  R('Record audio on the phone', 'T1429', 'Collection', [[P(/\.RECORD_AUDIO$/)]]),
  R('Use the phone camera', 'T1512', 'Collection', [[P(/\.CAMERA$/)]]),
  R('Read the screen and taps (accessibility service)', 'T1417.002', 'Collection', [[P(/\.BIND_ACCESSIBILITY_SERVICE$/), D(/AccessibilityService;->/)]]),
  R('Draw over other apps', 'T1417.002', 'Credential Access', [[P(/\.SYSTEM_ALERT_WINDOW$/)]]),
  R('Start when the phone boots', 'T1624.001', 'Persistence', [[P(/\.RECEIVE_BOOT_COMPLETED$/)]]),
  R('Install other apps', 'T1407', 'Defense Evasion', [[P(/\.REQUEST_INSTALL_PACKAGES$/)]]),
  R('Read notifications', 'T1517', 'Collection', [[P(/\.BIND_NOTIFICATION_LISTENER_SERVICE$/)]]),
  R('Act as a device administrator', 'T1626.001', 'Privilege Escalation', [[P(/\.BIND_DEVICE_ADMIN$/), D(/DevicePolicyManager;->/)]]),
];

function normApi(name, nix) {
  let n = String(name || '');
  if (n.includes('!')) n = n.slice(n.indexOf('!') + 1);
  if (nix) n = n.replace(/^_+/, '').replace(/@.*$/, '');
  return n;
}

export function detectCapabilities({ model, strings, dotnet, apk }) {
  const nix = !model.format.startsWith('PE');
  const apis = new Set();
  for (const lib of model.imports || []) for (const f of lib.fns || []) if (f.name) apis.add(normApi(f.name, nix));
  if (dotnet?.pinvoke) for (const p of dotnet.pinvoke) apis.add(p.name);
  const pools = {
    api: [...apis],
    str: (strings || []).map((s) => s.text).filter((t) => t.length >= 4 && t.length < 400),
    net: dotnet?.memberRefs || [],
    perm: apk?.permissions || [],
    dex: apk?.methodRefs || [],
  };
  if (dotnet?.userStrings) pools.str = pools.str.concat(dotnet.userStrings);
  if (apk?.strings) pools.str = pools.str.concat(apk.strings);
  const found = [];
  for (const r of RULES) {
    if (r.os === 'win' && nix && !apk) continue;
    if (r.os === 'nix' && !nix) continue;
    const ev = [];
    let ok = true;
    for (const g of r.groups) {
      let hit = null;
      for (const c of g) {
        const v = pools[c.k].find((x) => c.re.test(x));
        if (v != null) { hit = { kind: c.k, value: v }; break; }
      }
      if (!hit) { ok = false; break; }
      if (!ev.some((e) => e.value === hit.value)) ev.push(hit);
    }
    if (ok) found.push({ name: r.name, attack: r.attack, tactic: r.tactic, weak: r.weak, evidence: ev });
  }
  // one entry per behaviour name
  const seen = new Set();
  return found.filter((c) => (seen.has(c.name) ? false : seen.add(c.name)));
}

export const TACTIC_ORDER = ['Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];

export function attackUrl(id) {
  const [t, sub] = id.split('.');
  return `https://attack.mitre.org/techniques/${t}/${sub ? sub + '/' : ''}`;
}

// Android: binary AndroidManifest.xml (AXML) and DEX bytecode files.

// Attribute names by resource id, for manifests whose name strings were stripped.
const ATTR_IDS = {
  0x01010003: 'name', 0x0101021b: 'versionCode', 0x0101021c: 'versionName', 0x0101020c: 'minSdkVersion',
  0x01010270: 'targetSdkVersion', 0x01010010: 'exported', 0x0101000f: 'debuggable', 0x01010280: 'allowBackup',
  0x010104ec: 'usesCleartextTraffic', 0x01010006: 'permission', 0x01010001: 'label', 0x01010002: 'icon',
  0x0101000e: 'enabled', 0x01010009: 'protectionLevel',
};

export function parseAxml(b) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u16 = (o) => dv.getUint16(o, true), u32 = (o) => dv.getUint32(o, true);
  if (u16(0) !== 0x0003) throw new Error('Not a binary XML file');
  let strings = [], resIds = [];
  const root = { tag: '#root', attrs: {}, children: [] };
  const stack = [root];
  let p = u16(2);
  while (p + 8 <= b.length) {
    const type = u16(p), hsize = u16(p + 2), size = u32(p + 4);
    if (size < 8) break;
    if (type === 0x0001) strings = readStringPool(b, p);
    else if (type === 0x0180) { resIds = []; for (let q = p + hsize; q < p + size; q += 4) resIds.push(u32(q)); }
    else if (type === 0x0102) {
      const ext = p + hsize;
      const name = strings[u32(ext + 4)] || '';
      const aStart = u16(ext + 8), aSize = u16(ext + 10), aCount = u16(ext + 12);
      const attrs = {};
      for (let i = 0; i < aCount; i++) {
        const a = ext + aStart + i * aSize;
        const ni = u32(a + 4);
        let an = strings[ni] || '';
        if ((!an || /^[^a-zA-Z]/.test(an)) && ATTR_IDS[resIds[ni]]) an = ATTR_IDS[resIds[ni]];
        const raw = u32(a + 8), dt = b[a + 15], data = u32(a + 16);
        let v;
        if (raw !== 0xffffffff) v = strings[raw];
        else if (dt === 0x12) v = data !== 0;
        else if (dt === 0x10) v = data | 0;
        else if (dt === 0x11) v = '0x' + data.toString(16);
        else if (dt === 0x01) v = '@0x' + data.toString(16);
        else if (dt === 0x03) v = strings[data];
        else v = data;
        attrs[an] = v;
      }
      const el = { tag: name, attrs, children: [] };
      stack[stack.length - 1].children.push(el);
      stack.push(el);
    } else if (type === 0x0103) {
      if (stack.length > 1) stack.pop();
    }
    p += size;
  }
  return root.children[0] || null;
}

function readStringPool(b, p) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const count = dv.getUint32(p + 8, true), flags = dv.getUint32(p + 16, true), start = dv.getUint32(p + 20, true);
  const utf8 = !!(flags & 0x100);
  const out = new Array(count);
  const td = new TextDecoder('utf-8');
  for (let i = 0; i < count; i++) {
    let o = p + start + dv.getUint32(p + dv.getUint16(p + 2, true) + i * 4, true);
    if (utf8) {
      o += b[o] & 0x80 ? 2 : 1; // utf-16 length
      let len = b[o];
      if (len & 0x80) { len = ((len & 0x7f) << 8) | b[o + 1]; o += 2; } else o += 1;
      out[i] = td.decode(b.subarray(o, o + len));
    } else {
      let len = dv.getUint16(o, true);
      if (len & 0x8000) { len = ((len & 0x7fff) << 16) | dv.getUint16(o + 2, true); o += 4; } else o += 2;
      let s = '';
      for (let k = 0; k < len; k++) s += String.fromCharCode(dv.getUint16(o + k * 2, true));
      out[i] = s;
    }
  }
  return out;
}

const DANGEROUS = /\.(READ_SMS|RECEIVE_SMS|SEND_SMS|RECEIVE_MMS|READ_CONTACTS|WRITE_CONTACTS|READ_CALL_LOG|WRITE_CALL_LOG|PROCESS_OUTGOING_CALLS|CALL_PHONE|READ_PHONE_STATE|READ_PHONE_NUMBERS|ANSWER_PHONE_CALLS|RECORD_AUDIO|CAMERA|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|ACCESS_BACKGROUND_LOCATION|BODY_SENSORS|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE|READ_MEDIA_IMAGES|READ_MEDIA_VIDEO|READ_MEDIA_AUDIO|GET_ACCOUNTS|BIND_ACCESSIBILITY_SERVICE|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|BIND_DEVICE_ADMIN|BIND_NOTIFICATION_LISTENER_SERVICE|PACKAGE_USAGE_STATS|QUERY_ALL_PACKAGES|WRITE_SETTINGS|USE_FULL_SCREEN_INTENT|READ_PRIVILEGED_PHONE_STATE|INSTALL_PACKAGES|DELETE_PACKAGES)$/;

export function manifestInfo(root) {
  if (!root) return null;
  const pkg = root.attrs.package || '';
  const kids = (el, tag) => el.children.filter((c) => c.tag === tag);
  const sdk = kids(root, 'uses-sdk')[0]?.attrs || {};
  const perms = [...new Set(root.children.filter((c) => /^uses-permission/.test(c.tag)).map((c) => c.attrs.name).filter(Boolean))];
  const app = kids(root, 'application')[0];
  const full = (n) => (n && n.startsWith('.') ? pkg + n : n && !n.includes('.') ? `${pkg}.${n}` : n || '');
  const comps = [];
  for (const c of app ? app.children : []) {
    if (!/^(activity|activity-alias|service|receiver|provider)$/.test(c.tag)) continue;
    const actions = c.children.filter((x) => x.tag === 'intent-filter').flatMap((f) => f.children.filter((x) => x.tag === 'action').map((x) => x.attrs.name)).filter(Boolean);
    const hasFilter = c.children.some((x) => x.tag === 'intent-filter');
    const exported = c.attrs.exported === undefined ? hasFilter : c.attrs.exported === true;
    comps.push({ kind: c.tag, name: full(c.attrs.name), exported, permission: c.attrs.permission || '', actions });
  }
  const launcher = comps.find((c) => c.actions.includes('android.intent.action.MAIN'));
  return {
    package: pkg,
    versionName: String(root.attrs.versionName ?? ''),
    versionCode: root.attrs.versionCode ?? '',
    minSdk: sdk.minSdkVersion ?? '',
    targetSdk: sdk.targetSdkVersion ?? '',
    permissions: perms,
    dangerous: perms.filter((p) => DANGEROUS.test(p)),
    app: {
      name: full(app?.attrs.name),
      debuggable: app?.attrs.debuggable === true,
      allowBackup: app?.attrs.allowBackup !== false,
      cleartext: app?.attrs.usesCleartextTraffic === true,
    },
    components: comps,
    launcher: launcher?.name || '',
  };
}

/* ---------- DEX ---------- */

export const isDex = (b) => b.length > 0x70 && b[0] === 0x64 && b[1] === 0x65 && b[2] === 0x78 && b[3] === 0x0a;

export function parseDex(b) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u16 = (o) => dv.getUint16(o, true), u32 = (o) => dv.getUint32(o, true);
  const version = String.fromCharCode(b[4], b[5], b[6]);
  const nStr = u32(56), oStr = u32(60), nType = u32(64), oType = u32(68);
  const nMeth = u32(88), oMeth = u32(92), nClass = u32(96), oClass = u32(100);
  const td = new TextDecoder('utf-8', { fatal: false });
  const strings = new Array(nStr);
  for (let i = 0; i < nStr; i++) {
    let o = u32(oStr + i * 4);
    while (b[o] & 0x80) o++; // skip uleb128 length
    o++;
    let e = o;
    while (e < b.length && b[e]) e++;
    strings[i] = td.decode(b.subarray(o, e));
  }
  const types = new Array(nType);
  for (let i = 0; i < nType; i++) types[i] = strings[u32(oType + i * 4)];
  const methodRefs = new Array(nMeth);
  for (let i = 0; i < nMeth; i++) {
    const o = oMeth + i * 8;
    methodRefs[i] = `${types[u16(o)]}->${strings[u32(o + 4)]}`;
  }
  const classes = new Array(nClass);
  for (let i = 0; i < nClass; i++) classes[i] = types[u32(oClass + i * 32)];
  return { version, strings, types, methodRefs, classes };
}

// Java-style name from a DEX type descriptor: Lcom/foo/Bar; -> com.foo.Bar
export const javaName = (d) => (d && d[0] === 'L' ? d.slice(1, -1).replace(/\//g, '.') : d);

// Group class names by package, to show which libraries an app bundles.
export function packageSummary(classes, depth = 3) {
  const m = new Map();
  for (const c of classes) {
    const parts = javaName(c).split('.');
    parts.pop();
    const key = parts.slice(0, depth).join('.') || '(default package)';
    m.set(key, (m.get(key) || 0) + 1);
  }
  return [...m].sort((a, b) => b[1] - a[1]);
}

const DEX_FLAGS = [
  [/SmsManager;->send(Text|Multipart|Data)Message/, 'Sends SMS'],
  [/(DexClassLoader|InMemoryDexClassLoader|PathClassLoader);-><init>/, 'Loads extra code at runtime'],
  [/Runtime;->exec/, 'Runs shell commands'],
  [/TelephonyManager;->(getDeviceId|getImei|getSubscriberId|getLine1Number|getSimSerialNumber)/, 'Reads phone identifiers'],
  [/AccessibilityService;->|AccessibilityNodeInfo;->performAction/, 'Uses accessibility to read or tap the screen'],
  [/DevicePolicyManager;->(lockNow|wipeData|resetPassword)/, 'Device admin actions'],
  [/PackageManager;->(getInstalledPackages|getInstalledApplications)/, 'Lists installed apps'],
  [/Cipher;->(getInstance|doFinal)/, 'Encryption'],
  [/(HttpURLConnection|OkHttpClient|Volley|Retrofit)/, 'Network requests'],
  [/Ljava\/lang\/reflect\/Method;->invoke/, 'Reflection calls'],
  [/LocationManager;->(requestLocationUpdates|getLastKnownLocation)|FusedLocationProviderClient;->/, 'Reads location'],
  [/MediaRecorder;->(start|setAudioSource)|AudioRecord;->startRecording/, 'Records audio'],
  [/ContentResolver;->query/, 'Queries content providers (contacts, SMS, call log)'],
  [/Base64;->decode/, 'Decodes Base64'],
  [/System;->loadLibrary/, 'Loads native libraries'],
  [/WebView;->(addJavascriptInterface|loadUrl)/, 'WebView with JavaScript bridge'],
];

export function dexFlags(methodRefs) {
  const out = [];
  for (const [re, label] of DEX_FLAGS) {
    const hits = [...new Set(methodRefs.filter((m) => re.test(m)))];
    if (hits.length) out.push({ label, hits: hits.slice(0, 10) });
  }
  return out;
}

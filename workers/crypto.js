// Cloudflare Workers 端 AES-128-GCM 加解密（WebCrypto 原生，零依赖）
// 与 fastime Go 端的帧格式逐字节互通：
//
//   帧 = [u32be 明文长度][12B 随机 nonce][密文 + 16B GCM tag]
//   GET 参数中的帧 = base64url(无填充) 编码
//
// 密钥：base64 编码的 16 字节 AES-128 密钥，建议放 Workers 密钥/环境变量。

// ---------- 密钥导入 ----------
let _keyPromise = null;
function getKey(env) {
  if (!_keyPromise) {
    const raw = Uint8Array.from(atob(env.ENC_KEY_B64), c => c.charCodeAt(0));
    if (raw.length !== 16) throw new Error("ENC_KEY_B64 必须是 16 字节");
    _keyPromise = crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  return _keyPromise;
}

// ---------- base64url ----------
export function b64urlEncode(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
export function b64urlDecode(str) {
  str = str.replaceAll("-", "+").replaceAll("_", "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// ---------- 加密：明文 → 单帧 ----------
export async function encryptFrame(env, plain /* Uint8Array */) {
  const key = await getKey(env);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  // WebCrypto 输出 = 密文 || tag，与 Go 的 aead.Seal 完全一致
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain));
  const frame = new Uint8Array(4 + 12 + ct.length);
  new DataView(frame.buffer).setUint32(0, plain.length);
  frame.set(nonce, 4);
  frame.set(ct, 16);
  return frame;
}

// ---------- 解密：帧 → 明文（支持多帧拼接的流） ----------
export async function decryptFrames(env, data /* Uint8Array */) {
  const key = await getKey(env);
  const out = [];
  let off = 0;
  while (off < data.length) {
    const n = new DataView(data.buffer, data.byteOffset + off).getUint32(0);
    const nonce = data.subarray(off + 4, off + 16);
    const ct = data.subarray(off + 16, off + 16 + n + 16);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct));
    out.push(pt);
    off += 16 + n + 16;
  }
  // 合并输出
  const total = out.reduce((a, b) => a + b.length, 0);
  const merged = new Uint8Array(total);
  let o = 0;
  for (const p of out) { merged.set(p, o); o += p.length; }
  return merged;
}

// ---------- 解密：GET 紧凑帧（nonce||ct+tag，无长度头） ----------
export async function decryptCompact(env, data /* Uint8Array */) {
  const key = await getKey(env);
  const nonce = data.subarray(0, 12);
  const ct = data.subarray(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct));
}

// ---------- 响应加密：多帧流式输出（大响应分块，内存恒定） ----------
export function encryptStream(env, plain /* Uint8Array */, chunkSize = 64 * 1024) {
  return new ReadableStream({
    async start(controller) {
      for (let off = 0; off < plain.length; off += chunkSize) {
        controller.enqueue(await encryptFrame(env, plain.subarray(off, off + chunkSize)));
      }
      controller.close();
    },
  });
}

// ---------- 完整 Worker 示例（上游服务端） ----------
export default {
  async fetch(request, env) {
    let plain;
    if (request.method === "GET") {
      const enc = new URL(request.url).searchParams.get("time");
      if (!enc) return new Response("missing time=", { status: 400 });
      plain = await decryptCompact(env, b64urlDecode(enc));     // GET: time= 紧凑帧解密
    } else if (request.method === "POST") {
      plain = await decryptFrames(env, new Uint8Array(await request.arrayBuffer())); // POST: body 解密
    } else {
      return new Response("method not allowed", { status: 405 });
    }

    // ... 业务处理 plain ...

    const result = new TextEncoder().encode("echo:" + new TextDecoder().decode(plain));
    return new Response(encryptStream(env, result), {
      headers: { "Content-Type": "application/octet-stream" },
    });
  },
};

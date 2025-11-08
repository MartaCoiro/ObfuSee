import re
import random
import string
import base64
import os, json, secrets

# libreria per cifrare i literal in fase di trasformazione (build-side)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None  # se manca, lo segnaliamo nelle modifiche


# =========================
#  Helper comuni
# =========================

def wrap_opaque(testo: str) -> str:
    return f"<opaque>{testo}</opaque>"

def _apply_on_non_opaque(codice: str, transform_fn):
    """Applica transform_fn solo nei segmenti NON compresi tra <opaque>...</opaque>."""
    out, i = [], 0
    OPEN, CLOSE = "<opaque>", "</opaque>"
    while True:
        start = codice.find(OPEN, i)
        if start == -1:
            out.append(transform_fn(codice[i:])); break
        out.append(transform_fn(codice[i:start]))
        end = codice.find(CLOSE, start)
        if end == -1:  # tag aperto ma non chiuso: lascia così
            out.append(codice[start:]); break
        out.append(codice[start:end+len(CLOSE)])
        i = end + len(CLOSE)
    return "".join(out)

def _sostituisci_stringhe(segmento: str, gen_call_fn):
    """Sostituisce i literal stringa in 'segmento' con quanto restituito da gen_call_fn(s)."""
    pat = r'"([^"]+)"'
    def repl(m):
        s = m.group(1)
        if not s:
            return m.group(0)
        return gen_call_fn(s)
    return re.sub(pat, repl, segmento)


def _riordina_import_funzioni(codice: str, linguaggio: str) -> str:
    """
    Sposta SOLO i blocchi funzione iniettati (marcati con OBFUSEE_FN) tra le importazioni e il resto.
    Non sposta i call-site <opaque>.
    """
    # 1) Estrai blocchi <opaque>... controllando il marker OBFUSEE_FN
    fun_blocks = []
    kept = []
    pos = 0
    for m in re.finditer(r'<opaque>([\s\S]*?)</opaque>', codice):
        kept.append(codice[pos:m.start()])
        inner = m.group(1)
        full = m.group(0)
        if "OBFUSEE_FN" in inner:
            fun_blocks.append(full)   # spostiamo questi
        else:
            kept.append(full)         # lasciamo al loro posto i call-site
        pos = m.end()
    kept.append(codice[pos:])
    rest = "".join(kept)

    # 2) Raccogli righe import in 'rest'
    lines = rest.splitlines()
    import_lines, other_lines = [], []
    def is_import(line: str) -> bool:
        s = line.strip()
        if linguaggio == "c":            return s.startswith("#include")
        if linguaggio == "python":       return s.startswith("import ") or s.startswith("from ")
        if linguaggio == "java":         return s.startswith("import ")
        if linguaggio == "javascript":   return s.startswith("import ") or s.startswith("const ") and "require(" in s
        if linguaggio == "rust":         return s.startswith("use ") or "extern crate" in s
        return False

    for ln in lines:
        if is_import(ln):
            import_lines.append(ln)
        else:
            other_lines.append(ln)

    # 3) Ricomponi: import, funzioni iniettate, resto
    parts = []
    if import_lines:
        parts.append("\n".join(import_lines))
    if fun_blocks:
        parts.append("\n\n".join(fun_blocks))
    parts.append("\n".join(other_lines))
    return "\n\n".join(p for p in parts if p.strip())


def genera_nome_random():
    return ''.join(random.choices(string.ascii_letters, k=6))


# =========================
#  STEP 1 – Offuscamento lessicale
# =========================
def offuscamento_lessicale(codice, linguaggio="c"):
    parole_riservate = {
        "c": {
            "keywords": {"int", "char", "float", "double", "return", "if", "else", "while", "for", "switch", "case",
                         "break", "continue", "struct", "void", "const", "include", "define", "printf", "scanf",
                         "sizeof", "main"},
            "regex": r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
        },
        "python": {
            "keywords": {"def", "return", "if", "else", "elif", "for", "while", "break", "continue", "print", "input",
                         "import", "from", "as", "pass", "class", "in", "is", "not", "and", "or", "with", "lambda",
                         "try", "except", "finally", "True", "False", "None", "__name__"},
            "regex": r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
        },
        "java": {
            "keywords": {"int", "float", "double", "char", "public", "static", "void", "class", "if", "else", "new",
                         "for", "while", "return", "import", "package", "System", "out", "print", "println", "String",
                         "boolean", "true", "false", "main"},
            "regex": r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
        },
        "javascript": {
            "keywords": {"function", "let", "const", "var", "return", "if", "else", "for", "while", "true", "false",
                         "console", "log"},
            "regex": r'\b[a-zA-Z_$][a-zA-Z0-9_$]*\b'
        },
        "rust": {
            "keywords": {"fn", "let", "mut", "pub", "use", "crate", "impl", "struct", "enum", "match", "if", "else",
                         "loop", "for", "while", "return", "break", "continue", "mod", "super", "Self", "main"},
            "regex": r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
        }
    }

    config = parole_riservate.get(linguaggio, parole_riservate["c"])
    keyword_set = config["keywords"]
    regex = config["regex"]

    righe = codice.splitlines()
    intestazioni = [r for r in righe if (
        r.strip().startswith("#include") or
        r.strip().startswith("import") or
        r.strip().startswith("using") or
        r.strip().startswith("package")
    )]
    resto = "\n".join(r for r in righe if r not in intestazioni)

    identificatori = set(re.findall(regex, resto))
    mapping = {}
    modifiche = [{
        "descrizione": "📌 Offuscamento lessicale attivo. Nomi resi non interpretabili (rispetto della sintassi del linguaggio)."
    }]

    letters = "abcdefghijklmnopqrstuvwxyz"
    alnum   = "abcdefghijklmnopqrstuvwxyz0123456789"
    candidati = [id for id in identificatori if id not in keyword_set]

    for originale in candidati:
        nuovo = random.choice(letters) + random.choice(alnum)  # prima lettera sempre alfabetica
        while nuovo in keyword_set or nuovo in mapping.values():
            nuovo = random.choice(letters) + random.choice(alnum)
        mapping[originale] = nuovo
        modifiche.append({
            "origine": originale,
            "nuovo": nuovo,
            "descrizione": f"🧠 '{originale}' → '{nuovo}'"
        })

    def sostituisci(m):
        parola = m.group(0)
        return mapping.get(parola, parola)

    offuscato = re.sub(regex, sostituisci, resto)
    codice_finale = "\n".join(intestazioni) + "\n\n" + offuscato
    return codice_finale.strip(), modifiche


# =========================
#  STEP 3 – Trasformazione dei dati  (⚠️ esegui PRIMA dello Step 2)
# =========================
def trasformazione_dati(codice, linguaggio="c"):
    modifiche = [{"descrizione": "🔄 Trasformazione dei dati: inserimento di equivalenze logiche/aritmetiche ."}]
    codice_modificato = codice

    def wrap(testo): return f"<opaque>{testo}</opaque>"

    if linguaggio == "c":
        codice_modificato = re.sub(r'(\w+)\s*!=\s*0',
                                   lambda m: wrap(f"({m.group(1)} == {m.group(1)} && {m.group(1)} != '\\0')"),
                                   codice_modificato)
        modifiche.append({"descrizione": "🧪 x!=0 → (x==x && x!='\\0')"})

        codice_modificato = re.sub(r'if\s*\(\s*(\w+)\s*==\s*(\w+)\s*\)',
                                   lambda m: wrap(f"if (!({m.group(1)} < {m.group(2)} || {m.group(2)} < {m.group(1)}))"),
                                   codice_modificato)
        modifiche.append({"descrizione": "🧩 a==b → !(a<b || b<a)"})

        codice_modificato = re.sub(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+);',
                                   lambda m: wrap(f"{m.group(1)} = (({m.group(2)} == {m.group(2)}) ? {m.group(2)} : {m.group(3)}) + (({m.group(3)} == {m.group(3)}) ? {m.group(3)} : {m.group(2)});"),
                                   codice_modificato)
        modifiche.append({"descrizione": "➕ Somma offuscata (condizionale)"})

        codice_modificato = re.sub(r'(\w+)\s*=\s*(\w+)\s*-\s*(\w+);',
                                   lambda m: wrap(f"{m.group(1)} = (({m.group(2)} == {m.group(2)}) ? {m.group(2)} : {m.group(3)}) + (({m.group(3)} == {m.group(3)}) ? -{m.group(3)} : -{m.group(2)});"),
                                   codice_modificato)
        modifiche.append({"descrizione": "➖ Sottrazione offuscata (negazione)"})

    elif linguaggio == "python":
        codice_modificato = re.sub(r'(\w+)\s*==\s*(\w+)',
                                   lambda m: wrap(f"not ({m.group(1)} < {m.group(2)} or {m.group(2)} < {m.group(1)})"),
                                   codice_modificato)
        modifiche.append({"descrizione": "🧩 a==b → not(a<b or b<a)"})

    return codice_modificato, modifiche


# =========================
#  STEP 2 – Offuscamento del flusso (opaque predicates)
# =========================
def offuscamento_flusso(codice, linguaggio="c"):
    modifiche = [{"descrizione": "🔀 Offuscamento del flusso: inseriti opaque predicates,ovvero condizioni inutili ma sempre vere ."}]
    codice_modificato = codice

    def nome_var():
        return random.choice(["b7", "z", "c9", "w2", "x1"])

    def inserisci_blocchi(codice_base, pattern, blocchi):
        matches = list(re.finditer(pattern, codice_base))
        offset = 0
        for i, match in enumerate(matches):
            pos = match.end() + offset   # ⬅️ inseriamo DOPO il token matchato
            insert = "\n<opaque>\n" + blocchi[i % len(blocchi)] + "\n</opaque>\n"
            codice_base = codice_base[:pos] + insert + codice_base[pos:]
            offset += len(insert)
        return codice_base

    var = nome_var()
    if linguaggio in ("c", "java", "javascript", "rust"):
        opaque_blocks = [
            f"if (({var} * {var} + 1) > 0) {{ /* sempre vero */ }}",
            f"if ((int){var} % 2 == 0 || 1) {{ /* condizione inutile */ }}"
        ]
        pattern = r";"
        codice_modificato = inserisci_blocchi(codice_modificato, pattern, opaque_blocks)

    elif linguaggio == "python":
        opaque_blocks = [f"if {var} == {var}:\n    pass",
                         f"if len('{var}') >= 0:\n    pass"]
        pattern = r"\n"
        codice_modificato = inserisci_blocchi(codice_modificato, pattern, opaque_blocks)

    return codice_modificato, modifiche


# =========================
#  STEP 4 – Anti-Debugging
# =========================
def anti_debugging(codice, linguaggio="c"):
    modifiche = [{"descrizione": "🛡️ Anti-Debugging: controllo debugger inserito all'avvio del main."}]

    if linguaggio == "c":
        # funzione con marker OBFUSEE_FN (per riordino)
        debug_func = wrap_opaque('''/* OBFUSEE_FN */
void anti_debug_check() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        raise(SIGKILL);
    }
}''')

        # 1) assicurati che gli include base ci siano
        righe = codice.splitlines()
        includes = [r for r in righe if r.strip().startswith("#include")]
        corpo = "\n".join(r for r in righe if r not in includes)

        need = []
        for inc in ["#include <signal.h>", "#include <unistd.h>", "#include <sys/ptrace.h>"]:
            if not any(inc in x for x in includes):
                need.append(inc)
        header = "\n".join(includes + need)

        # 2) inserisci la chiamata dentro al main (dopo la { )
        def inject_call(m):
            return m.group(0) + "\n" + wrap_opaque("    anti_debug_check();")

        corpo = re.sub(r'int\s+main\s*\([^)]*\)\s*\{', inject_call, corpo, count=1)

        codice_modificato = header + "\n\n" + debug_func + "\n\n" + corpo
        # riordina: import, funzioni iniettate, resto
        codice_modificato = _riordina_import_funzioni(codice_modificato, "c")
        return codice_modificato, modifiche

    elif linguaggio == "python":
        debug_func = wrap_opaque('''# OBFUSEE_FN
def anti_debug_check():
    import sys, os
    if sys.gettrace():
        os._exit(1)
''')
        codice_modificato = debug_func + "\n\n" + codice
        codice_modificato = _riordina_import_funzioni(codice_modificato, "python")
        # inserisci richiamo a runtime se presente il main-guard
        codice_modificato = codice_modificato.replace(
            'if __name__ == "__main__":',
            'if __name__ == "__main__":\n' + wrap_opaque("    anti_debug_check()"), 1
        )
        return codice_modificato, modifiche

    # Java/JS/Rust: omessi per brevità — stessa logica (funzione con marker + inserimento nel main)
    return codice, modifiche


# =========================
#  STEP 5 – Offuscamento dati (Base64)  (NON è cifratura)
# =========================
def offuscamento_crittografia(codice, linguaggio="c"):
    modifiche = [{"descrizione": "🔐 Offuscamento (Base64): stringhe codificate e decodificate a runtime. (NON è cifratura)"}]

    def gen_call(s: str) -> str:
        if linguaggio == "c":          return wrap_opaque(f'decode_base64("{base64.b64encode(s.encode()).decode()}")')
        if linguaggio == "python":     return wrap_opaque(f'decode_string("{base64.b64encode(s.encode()).decode()}")')
        if linguaggio == "java":       return wrap_opaque(f'Decoder.decode("{base64.b64encode(s.encode()).decode()}")')
        if linguaggio == "javascript": return wrap_opaque(f'decodeBase64("{base64.b64encode(s.encode()).decode()}")')
        if linguaggio == "rust":       return wrap_opaque(f'decode_base64("{base64.b64encode(s.encode()).decode()}")')
        return s

    # sostituisci SOLO fuori da <opaque>
    codice_modificato = _apply_on_non_opaque(codice, lambda seg: _sostituisci_stringhe(seg, gen_call))

    # inietta una sola volta le funzioni (con marker OBFUSEE_FN per riordino)
    if linguaggio == "c":
        fn = wrap_opaque('''/* OBFUSEE_FN */
char* decode_base64(const char* encoded) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len = strlen(encoded);
    char *decoded = malloc(len);
    int val = 0, valb = -8, idx = 0;
    for (int i = 0; i < len; i++) {
        char *p = strchr(table, encoded[i]);
        if (p) val = (val << 6) + (p - table);
        else continue;
        valb += 6;
        if (valb >= 0) {
            decoded[idx++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    decoded[idx] = '\\0';
    return decoded;
}''')

    elif linguaggio == "python":
        fn = wrap_opaque('''# OBFUSEE_FN
import base64
def decode_string(encoded):
    return base64.b64decode(encoded).decode("utf-8")''')

    elif linguaggio == "java":
        fn = wrap_opaque('''/* OBFUSEE_FN */
import java.util.Base64;
class Decoder {
    public static String decode(String encoded) {
        return new String(Base64.getDecoder().decode(encoded));
    }
}''')

    elif linguaggio == "javascript":
        fn = wrap_opaque('''/* OBFUSEE_FN */
function decodeBase64(encoded) {
    return atob(encoded);
}''')

    elif linguaggio == "rust":
        fn = wrap_opaque('''// OBFUSEE_FN
fn decode_base64(encoded: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    String::from_utf8(general_purpose::STANDARD.decode(encoded).unwrap()).unwrap()
}''')
    else:
        fn = ""

    codice_modificato = fn + "\n\n" + codice_modificato
    codice_modificato = _riordina_import_funzioni(codice_modificato, linguaggio)
    return codice_modificato, modifiche


# =========================
#  STEP 6 – Cifratura AEAD (chiave dal server)
# =========================

AEAD_REGISTRY = {}  # id -> key_base64 (solo lato server per /k)

def offuscamento_aead(codice, linguaggio="c"):
    modifiche = [{"descrizione": "🔐 Cifratura AEAD: il testo è cifrato; a runtime si chiede la chiave al server per leggerlo"}]
    if AESGCM is None:
        modifiche.append({"descrizione": "❗ Manca 'cryptography'. Installa: pip install cryptography"})
        return codice, modifiche

    def sigilla(plaintext: str):
        key = os.urandom(32)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)  # ct||tag
        blob_b64 = base64.b64encode(nonce + ct).decode()
        _id = secrets.token_hex(8)
        AEAD_REGISTRY[_id] = base64.b64encode(key).decode()
        return blob_b64, _id

    def gen_call(s: str) -> str:
        blob, _id = sigilla(s)
        if linguaggio == "c":          return wrap_opaque(f'dec_aead("{blob}", "{_id}")')
        if linguaggio == "python":     return wrap_opaque(f'dec_aead("{blob}", "{_id}")')
        if linguaggio == "java":       return wrap_opaque(f'AEAD.dec("{blob}", "{_id}")')
        if linguaggio == "javascript": return wrap_opaque(f'decAead("{blob}", "{_id}")')
        if linguaggio == "rust":       return wrap_opaque(f'dec_aead("{blob}", "{_id}")')
        return s

    # sostituisci SOLO fuori da <opaque> (non toccare funzioni già iniettate)
    codice_modificato = _apply_on_non_opaque(codice, lambda seg: _sostituisci_stringhe(seg, gen_call))

    # Inietta funzione di decifrazione con marker OBFUSEE_FN (senza #include dentro)
    if linguaggio == "python":
        fn = wrap_opaque('''# OBFUSEE_FN
import os, json, base64, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def get_runtime_key(key_id: str) -> bytes:
    base = os.environ.get("AEAD_KEY_SERVER", "http://localhost:5000")
    token = os.environ.get("AEAD_TOKEN", "")
    req = urllib.request.Request(f"{base}/k?id=" + key_id)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=3) as r:
        data = json.loads(r.read().decode())
    return base64.b64decode(data["key_b64"])
def dec_aead(b64_blob: str, key_id: str) -> str:
    raw = base64.b64decode(b64_blob)
    nonce, ct_tag = raw[:12], raw[12:]
    key = get_runtime_key(key_id)
    pt = AESGCM(key).decrypt(nonce, ct_tag, None)
    return pt.decode("utf-8")''')

    elif linguaggio == "javascript":
        fn = wrap_opaque('''/* OBFUSEE_FN */
async function getRuntimeKey(keyId){
  const base = process.env.AEAD_KEY_SERVER || "http://localhost:5000";
  const token = process.env.AEAD_TOKEN || "";
  const res = await fetch(`${base}/k?id=${keyId}`, {
    headers: token ? { "Authorization": `Bearer ${token}` } : {}
  });
  const data = await res.json();
  return Buffer.from(data.key_b64, "base64");
}
async function decAead(b64Blob, keyId){
  const raw = Buffer.from(b64Blob, "base64");
  const nonce = raw.subarray(0,12);
  const ctTag = raw.subarray(12);
  const key = await getRuntimeKey(keyId);
  const crypto = require("crypto");
  const tag = ctTag.subarray(ctTag.length-16);
  const ct = ctTag.subarray(0, ctTag.length-16);
  const dec = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  dec.setAuthTag(tag);
  const pt = Buffer.concat([dec.update(ct), dec.final()]);
  return pt.toString("utf8");
}''')

    elif linguaggio == "java":
        fn = wrap_opaque('''/* OBFUSEE_FN */
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*; import java.io.*;
class AEAD {
    private static byte[] httpGetKey(String keyId) throws Exception {
        String base = System.getenv().getOrDefault("AEAD_KEY_SERVER", "http://localhost:5000");
        String token = System.getenv().getOrDefault("AEAD_TOKEN", "");
        URL u = new URL(base + "/k?id=" + keyId);
        HttpURLConnection c = (HttpURLConnection)u.openConnection();
        c.setRequestMethod("GET");
        if (!token.isEmpty()) c.setRequestProperty("Authorization", "Bearer " + token);
        try (InputStream is = c.getInputStream();
             BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
            StringBuilder sb = new StringBuilder(); String line;
            while((line = br.readLine()) != null) sb.append(line);
            String json = sb.toString();
            String b64 = json.replaceAll(".*\\\"key_b64\\\"\\s*:\\s*\\\"([^\\\"]+)\\\".*", "$1");
            return Base64.getDecoder().decode(b64);
        }
    }
    public static String dec(String b64Blob, String keyId) throws Exception {
        byte[] raw = Base64.getDecoder().decode(b64Blob);
        byte[] nonce = java.util.Arrays.copyOfRange(raw, 0, 12);
        byte[] ctTag = java.util.Arrays.copyOfRange(raw, 12, raw.length);
        byte[] tag = java.util.Arrays.copyOfRange(ctTag, ctTag.length-16, ctTag.length);
        byte[] ct  = java.util.Arrays.copyOfRange(ctTag, 0, ctTag.length-16);
        byte[] key = httpGetKey(keyId);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec k = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        c.init(Cipher.DECRYPT_MODE, k, spec);
        c.updateAAD(new byte[0]);
        byte[] out = new byte[ct.length + 16];
        System.arraycopy(ct, 0, out, 0, ct.length);
        System.arraycopy(tag, 0, out, ct.length, 16);
        byte[] pt = c.doFinal(out);
        return new String(pt, java.nio.charset.StandardCharsets.UTF_8);
    }
}''')

    elif linguaggio == "rust":
        fn = wrap_opaque('''// OBFUSEE_FN
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use base64::{engine::general_purpose, Engine as _};
fn get_runtime_key(id: &str) -> Vec<u8> {
    let base = std::env::var("AEAD_KEY_SERVER").unwrap_or("http://localhost:5000".into());
    let token = std::env::var("AEAD_TOKEN").unwrap_or_default();
    let client = reqwest::blocking::Client::new();
    let mut req = client.get(format!("{}/k?id={}", base, id));
    if !token.is_empty() { req = req.header("Authorization", format!("Bearer {}", token)); }
    let v: serde_json::Value = req.send().unwrap().json().unwrap();
    general_purpose::STANDARD.decode(v["key_b64"].as_str().unwrap()).unwrap()
}
fn dec_aead(b64_blob: &str, id: &str) -> String {
    let raw = general_purpose::STANDARD.decode(b64_blob).unwrap();
    let (nonce, ct_tag) = raw.split_at(12);
    let key = get_runtime_key(id);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let pt = cipher.decrypt(nonce.into(), ct_tag).unwrap();
    String::from_utf8(pt).unwrap()
}''')

    elif linguaggio == "c":
        # Niente #include qui: restano in testa al file (best practice)
        fn = wrap_opaque('''/* OBFUSEE_FN */
static unsigned char* _obf_b64dec(const char* b64, int* outlen){
    BIO *b = BIO_new_mem_buf(b64, -1);
    BIO *d = BIO_new(BIO_f_base64());
    b = BIO_push(d, b); BIO_set_flags(b, BIO_FLAGS_BASE64_NO_NL);
    unsigned char* buf = malloc(strlen(b64));
    *outlen = BIO_read(b, buf, strlen(b64));
    BIO_free_all(b); return buf;
}
static int get_runtime_key(const char* id, unsigned char** key_out){
    const char* k = getenv("AEAD_KEY_B64");
    if(!k) return 0;
    int L=0; unsigned char* kb = _obf_b64dec(k, &L);
    if(L != 32){ free(kb); return 0; }
    *key_out = kb; return 1;
}
char* dec_aead(const char* b64_blob, const char* id){
    int rawlen=0; unsigned char* raw = _obf_b64dec(b64_blob, &rawlen);
    if(!raw || rawlen<12+16){ free(raw); return NULL; }
    unsigned char *nonce = raw, *ct_tag = raw+12;
    int ctlen = rawlen - 12 - 16;
    unsigned char* key = NULL;
    if(!get_runtime_key(id, &key)){ free(raw); return NULL; }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    unsigned char* pt = malloc(ctlen+1);
    int outl=0; EVP_DecryptUpdate(ctx, pt, &outl, ct_tag, ctlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ct_tag+ctlen);
    int ok = EVP_DecryptFinal_ex(ctx, pt+outl, &outl);
    EVP_CIPHER_CTX_free(ctx); free(raw); free(key);
    if(!ok){ free(pt); return NULL; }
    pt[ctlen] = '\\0'; return (char*)pt;
}''')
    else:
        fn = ""

    # per C: garantire gli include necessari in testa
    if linguaggio == "c":
        # Se mancano, li aggiungiamo: poi il riordino li metterà prima delle funzioni
        headers = []
        need = ["#include <openssl/evp.h>", "#include <openssl/err.h>", "#include <stdlib.h>", "#include <string.h>"]
        lines = codice_modificato.splitlines()
        for inc in need:
            if not any(inc in x for x in lines):
                headers.append(inc)
        if headers:
            codice_modificato = "\n".join(headers) + "\n" + codice_modificato

    codice_modificato = fn + "\n\n" + codice_modificato
    codice_modificato = _riordina_import_funzioni(codice_modificato, linguaggio)

    return codice_modificato, modifiche

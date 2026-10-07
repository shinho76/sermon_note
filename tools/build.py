"""source/ -> index.html + data/*.enc  (gzip 압축 후 AES-GCM 암호화)

사용법:  SERMON_PW=비밀번호 python tools/build.py
- source/sermons/<연도>.json : 연도별 설교 배열 (비공개, .gitignore)
- source/app.html, source/app.js : 화면/로직 (암호화되어 data/app.enc 로 배포)
- tools/shell.html, tools/loader.js : 잠금 화면 + 복호화 로더 (공개)
- tools/salt.txt : PBKDF2 salt (공개해도 무방, 바꾸면 캐시된 파일과 호환되지 않음)
"""
import base64, glob, gzip, hashlib, hmac, json, os, secrets, shutil, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
ITER = 600000
pw = os.environ.get("SERMON_PW")
if not pw:
    sys.exit("SERMON_PW 환경변수에 비밀번호를 지정하세요.")

if not os.path.exists("tools/salt.txt"):
    open("tools/salt.txt", "w").write(base64.b64encode(secrets.token_bytes(16)).decode())
salt = base64.b64decode(open("tools/salt.txt").read().strip())
key = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITER, 32)
aes = AESGCM(key)
ivkey = hashlib.sha256(key + b"iv").digest()

def pack(obj):
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
    # 내용이 같으면 결과 파일도 같게(IV = HMAC(평문)) -> 바뀐 연도만 git diff에 잡힘.
    # 평문이 다르면 IV도 달라지므로 같은 키로 IV를 재사용하지 않는다.
    iv = hmac.new(ivkey, raw, hashlib.sha256).digest()[:12]
    return iv + aes.encrypt(iv, gzip.compress(raw, 9, mtime=0), None)

def read(p):
    return open(p, encoding="utf-8").read()

shutil.rmtree("data", ignore_errors=True)
os.makedirs("data/sermons")
manifest, h = [], hashlib.sha256()
for p in sorted(glob.glob("source/sermons/*.json")):
    year = os.path.basename(p)[:-5]
    items = json.load(open(p, encoding="utf-8"))
    items.sort(key=lambda s: s["id"])
    manifest += [{k: s[k] for k in ("id", "tab", "title", "text")} for s in items]
    blob = pack(items)
    open(f"data/sermons/{year}.enc", "wb").write(blob)
    h.update(blob)
manifest.sort(key=lambda s: s["id"])
for name, obj in (("manifest", manifest), ("app", {"html": read("source/app.html"), "js": read("source/app.js")})):
    blob = pack(obj)
    open(f"data/{name}.enc", "wb").write(blob)
    h.update(blob)

params = {"s": base64.b64encode(salt).decode(), "n": ITER, "v": h.hexdigest()[:10]}
loader = read("tools/loader.js").replace("__PARAMS__", json.dumps(params))
html = read("tools/shell.html").replace("<!--LOADER-->", "<script>\n" + loader + "</script>")
open("index.html", "w", encoding="utf-8", newline="\n").write(html)

total = sum(os.path.getsize(f) for f in glob.glob("data/**/*.enc", recursive=True))
print(f"sermons={len(manifest)} files={len(glob.glob('data/**/*.enc', recursive=True))} data={total:,}B index.html={os.path.getsize('index.html'):,}B v={params['v']}")

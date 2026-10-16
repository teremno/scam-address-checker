"""Build demo.mp4 for the Blockscout buildathon from real checker output.
Usage (from scam-address-checker/):  python demo/make_demo.py
Runs checker.py on the demo addresses, draws 1280x720 frames with Pillow, and joins them with ffmpeg."""
import json, os, subprocess, sys
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demo")
FR = os.path.join(DEMO, "frames")
os.makedirs(FR, exist_ok=True)
W, H = 1280, 720
BG, FG, MUTED, ACC = (14, 17, 23), (232, 236, 241), (139, 148, 158), (88, 166, 255)
RED, ORANGE, GREEN, YEL = (248, 81, 73), (240, 136, 62), (63, 185, 80), (210, 153, 34)
F = "C:/Windows/Fonts/"
sans = lambda s: ImageFont.truetype(F + "segoeui.ttf", s)
bold = lambda s: ImageFont.truetype(F + "segoeuib.ttf", s) if os.path.exists(F + "segoeuib.ttf") else sans(s)
mono = lambda s: ImageFont.truetype(F + "consola.ttf", s)

VICTIM = "0x1E227979f0b5BC691a70DEAed2e0F39a6F538FD5"
ATTACKER = "0xd9A1C3788D81257612E2581A6ea0aDa244853a91"
VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"


def run(args):
    p = subprocess.run([sys.executable, "-X", "utf8", "checker.py", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    return p.stdout.strip()


def split(out):
    """'Risk HIGH: 2 x, 0 y. Report: …' -> ['Risk HIGH', '  2 x', '  0 y']"""
    head, _, rest = out.split(". Report")[0].partition(": ")
    return [head] + ["  " + p for p in rest.split(", ")]


def frame(name, title, caption, draw_body):
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, W, 64], fill=(22, 27, 34))
    d.text((32, 14), "Scam Address Checker", font=bold(26), fill=ACC)
    d.text((W - 32, 20), "Blockscout PRO API Buildathon", font=sans(20), fill=MUTED, anchor="ra")
    if title:
        d.text((48, 92), title, font=bold(40), fill=FG)
    draw_body(im, d)
    d.rectangle([0, H - 86, W, H], fill=(0, 0, 0))
    d.text((W // 2, H - 43), caption, font=sans(28), fill=(255, 255, 255), anchor="mm")
    path = os.path.join(FR, name + ".png")
    im.save(path)
    return path


def lines(d, xy, items, font, gap=10):
    x, y = xy
    for text, color in items:
        d.text((x, y), text, font=font, fill=color)
        y += font.size + gap
    return y


def main():
    out_victim = run([VICTIM, "--pages", "6", "--to", ATTACKER])
    out_v1 = run([VITALIK, "--pages", "3"])
    out_v10 = run([VITALIK, "--chain", "10", "--pages", "2"])
    rv = json.load(open(os.path.join(ROOT, "reports", f"1_{VICTIM}.json"), encoding="utf-8"))
    frames = []

    def add(*a):
        frames.append(tuple(a[0]) if len(a) == 1 else tuple(a))

    add((frame("01_title", "", "Detect address poisoning before you lose funds", lambda im, d: (
        d.text((W // 2, 250), "Scam Address Checker", font=bold(72), fill=FG, anchor="mm"),
        d.text((W // 2, 330), "Address-poisoning detector built on the Blockscout PRO API", font=sans(32), fill=MUTED, anchor="mm"),
        d.text((W // 2, 420), "github.com/teremno/scam-address-checker", font=mono(28), fill=ACC, anchor="mm")))), 8)

    add((frame("02_problem", "The scam: look-alike addresses", "Wallets show only the start and the end of an address", lambda im, d: lines(d, (60, 170), [
        ("Example. Your real counterparty:  0x7a3F 91c2 … 5e0B 44d1", FG),
        ("Attacker's look-alike:            0x7a3F 08bE … 92aC 44d1", RED),
        ("What the wallet shows for both:   0x7a3F…44d1", YEL),
        ("", FG),
        ("1. Attacker generates an address with the same first/last characters", MUTED),
        ("2. Plants it in your history: zero-value or fake-token transfers", MUTED),
        ("3. You copy the 'familiar' address from history and send real funds", MUTED),
        ("", FG),
        ("May 2024: one wallet sent 1,155 WBTC to such a look-alike.", YEL)], sans(30)))), 20)

    add((frame("03_run", "Run it on the real 2024 case", "One command: wallet + the address you are about to pay", lambda im, d: (
        d.rounded_rectangle([40, 160, W - 40, 600], 12, fill=(1, 4, 9), outline=(48, 54, 61)),
        lines(d, (64, 186), [(f"$ python checker.py {VICTIM[:12]}… \\", GREEN),
                             (f"      --to {ATTACKER[:12]}…", GREEN), ("", FG)] +
              [(l, RED if l.startswith("Risk") else FG) for l in split(out_victim)] + [("", FG), (f"API calls: {rv['scanned']['api_calls']}  ·  "
               f"transfers scanned: {rv['scanned']['token_transfers']}  ·  chain: Ethereum", MUTED)], mono(24))))), 16)

    def body_lookalikes(im, d):
        y = 170
        d.text((60, y), f"Risk: HIGH", font=bold(34), fill=RED); y += 60
        for c in rv["lookalike_clusters"]:
            d.text((60, y), f"Pattern {c['pattern']}", font=bold(28), fill=FG); y += 42
            for la in c["lookalikes"]:
                tag = "  planted + REAL FUNDS SENT" if la["real_value_sent_to_it"] and la["planted_at"] else ("  planted" if la["planted_at"] else "")
                d.text((90, y), la["address"] + tag, font=mono(24), fill=RED if "REAL" in tag else ORANGE); y += 36
            y += 14
    add((frame("04_lookalikes", "Finding 1: planted look-alike addresses", "Two fakes of 0xd9A1…3a91 were planted; real WBTC went to one of them", body_lookalikes), 20))

    def body_fakes(im, d):
        y = lines(d, (60, 170), [(f"{f['symbol']:<6} {f['address'][:14]}…  {f['reasons'][0][:70]}", ORANGE) for f in rv["fake_tokens"]], mono(22), 14)
        d.text((60, y + 20), "Transfers the owner never signed:", font=bold(28), fill=FG)
        lines(d, (60, y + 70), [(f"{s['time'][:10]}  {s['token']:<5} → {s['to'][:14]}…  signed by {s['initiator'][:14]}…", RED)
                                for s in rv["spoofed_transfers"]], mono(22), 14)
    add((frame("05_fakes", "Finding 2: fake tokens and spoofed history", "\"WВТC\" uses Cyrillic В and Т to imitate WBTC", body_fakes), 20))

    def body_explorer(im, d):
        shot = Image.open(os.path.join(FR, "explorer.jpg")).convert("RGB")
        shot = shot.crop((80, 138, 790, 410))          # keep "Transaction details", drop banners and ads
        shot = shot.resize((1180, int(shot.height * 1180 / shot.width)))
        im.paste(shot, ((W - shot.width) // 2, 90))
    add((frame("06_explorer", "", "Every finding links to Blockscout Explorer as evidence", body_explorer), 12))

    add((frame("07_stop", "Check before sending", "Paste the address you are about to pay: STOP if it is a look-alike", lambda im, d: (
        d.text((60, 180), f"--to {ATTACKER}", font=mono(26), fill=FG),
        d.rounded_rectangle([60, 250, 520, 400], 16, fill=RED),
        d.text((290, 325), "STOP", font=bold(80), fill=(255, 255, 255), anchor="mm"),
        d.text((570, 255), "Why:", font=bold(28), fill=FG),
        lines(d, (570, 300), [(("• " if i == 0 else "   ") + part, ORANGE) for x in rv["recipient_check"]["reasons"]
                              for i, part in enumerate(__import__("textwrap").wrap(x, 44))], sans(24), 10)))), 15)

    add((frame("08_multichain", "No false alarm, multichain", "One PRO API key, any supported chain: --chain 10 for Optimism", lambda im, d: lines(d, (60, 180), [
        ("vitalik.eth on Ethereum:", FG), ("   " + split(out_v1)[0] + "  (nothing suspicious)", GREEN), ("", FG),
        ("vitalik.eth on Optimism (--chain 10):", FG), ("   " + split(out_v10)[0] + " " + split(out_v10)[2].strip(), ORANGE), ("", FG),
        ("Two addresses imitating 0xd8dA…6045 itself were found.", MUTED)], mono(22)))), 15)

    def box(d, xy, text, color, sub=""):
        x0, y0, x1, y1 = xy
        d.rounded_rectangle(xy, 14, fill=(22, 27, 34), outline=color, width=3)
        d.text(((x0 + x1) // 2, y0 + 34), text, font=bold(26), fill=color, anchor="mm")
        yy = y0 + 72
        for part in sub.split("\n"):
            d.text(((x0 + x1) // 2, yy), part, font=sans(19), fill=MUTED, anchor="mm")
            yy += 26

    def arrow(d, a, b):
        d.line([a, b], fill=MUTED, width=3)
        d.polygon([(b[0], b[1]), (b[0] - 12, b[1] - 7), (b[0] - 12, b[1] + 7)], fill=MUTED)

    def body_arch(im, d):
        box(d, (30, 210, 250, 400), "Input", ACC, "wallet address\n--to recipient\n--chain id")
        box(d, (310, 170, 630, 440), "Blockscout PRO API", GREEN, "address info + labels\nERC-20 transfers\n(token reputation)\nnative transactions\ntx signer lookup")
        box(d, (690, 170, 990, 440), "Detectors", ORANGE, "look-alike groups\nplanted addresses\nfake / homoglyph tokens\nspoofed transfers\nlosses, impersonators")
        box(d, (1050, 210, 1250, 400), "Report", YEL, "risk + STOP\nMarkdown / JSON\nExplorer links")
        arrow(d, (250, 305), (310, 305)); arrow(d, (630, 305), (690, 305)); arrow(d, (990, 305), (1050, 305))
        d.text((W // 2, 510), "Python + requests  ·  one PRO API key for every supported chain  ·  key sent in the Authorization header",
               font=sans(21), fill=MUTED, anchor="mm")
    add(frame("10_arch", "Architecture", "Blockscout is the only data source: no node, no indexer of our own", body_arch), 25)

    add(frame("11_api", "How the Blockscout PRO API powers it", "Token reputation and scam labels come straight from Blockscout", lambda im, d: lines(d, (60, 165), [
        ("GET /{chain}/api/v2/addresses/{a}", GREEN), ("    labels, is_scam flag, ENS: recipient check", MUTED),
        ("GET /{chain}/api/v2/addresses/{a}/token-transfers?type=ERC-20", GREEN), ("    paginated history + token reputation: fake tokens, planted look-alikes", MUTED),
        ("GET /{chain}/api/v2/addresses/{a}/transactions", GREEN), ("    native transfers: real counterparties and losses", MUTED),
        ("GET /{chain}/api/v2/transactions/{hash}", GREEN), ("    who really signed a suspicious transfer: spoofed history", MUTED),
        ("", FG), (f"Real case: {rv['scanned']['api_calls']} calls, {rv['scanned']['token_transfers']} transfers analysed in under 10 seconds", YEL)], mono(21), 8)), 20)

    def body_report(im, d):
        md = open(os.path.join(ROOT, "reports", f"1_{VICTIM}.md"), encoding="utf-8").read().splitlines()
        keep = [l for l in md if l.strip() and not l.startswith("---") and not l.startswith("How it works")][:17]
        clean = lambda l: "".join(ch for ch in l if ord(ch) < 0x2190 or ch in "→…·").replace("**", "").split("](")[0].replace("[", "")
        lines(d, (40, 160), [(clean(l)[:100],
                              RED if ("STOP" in l or "HIGH" in l) else (YEL if l.startswith("#") else FG)) for l in keep], mono(17), 6)
    add(frame("12_report", "The report a user gets", "Markdown for people, JSON for bots and dashboards", body_report), 20)

    add((frame("09_next", "Next (Sprint 2)", "Open source, MIT  ·  github.com/teremno/scam-address-checker", lambda im, d: lines(d, (60, 180), [
        ("•  Web UI: paste an address, get verdict and evidence", FG),
        ("•  Watch mode with Telegram alerts when a look-alike is planted", FG),
        ("•  Cross-chain view of the same attacker", FG),
        ("•  Precision tests on a labelled set of known poisoning cases", FG)], sans(32)))), 12)

    # ffmpeg concat with per-frame durations
    lst = os.path.join(FR, "list.txt")
    with open(lst, "w", encoding="utf-8") as fh:
        for path, dur in frames:
            fh.write(f"file '{path.replace(os.sep, '/')}'\nduration {dur}\n")
        fh.write(f"file '{frames[-1][0].replace(os.sep, '/')}'\n")
    out = os.path.join(DEMO, "demo.mp4")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", lst, "-vf", "fps=30,format=yuv420p",
                    "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-movflags", "+faststart", out], check=True)
    print("video:", out, "frames:", len(frames), "seconds:", sum(d for _, d in frames))


main()

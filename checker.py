"""Scam Address Checker: detect address-poisoning traces around a wallet using the Blockscout API.

Usage:
  python checker.py <address> [--chain 1] [--to <intended_recipient>] [--pages 10] [--out reports/]

Reads BLOCKSCOUT_API_KEY from the environment (Blockscout PRO API, https://dev.blockscout.com).
Without a key it falls back to the public Blockscout instance of the chain (development only).
Writes <out>/<chain>_<address>.json and .md and prints a short summary.
"""
import argparse, json, os, sys, time, unicodedata
from collections import defaultdict
from datetime import datetime, timezone

import requests

PUBLIC = {1: "https://eth.blockscout.com", 8453: "https://base.blockscout.com", 10: "https://optimism.blockscout.com",
          42161: "https://arbitrum.blockscout.com", 100: "https://gnosis.blockscout.com", 137: "https://polygon.blockscout.com"}
# Canonical contracts of tokens that poisoners imitate most often (lowercase). Anything else with the same symbol is a copy.
CANONICAL = {
    1: {"USDT": "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "WBTC": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", "WETH": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "DAI": "0x6b175474e89094c44da98b954eedeac495271d0f"},
    8453: {"USDC": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "WETH": "0x4200000000000000000000000000000000000006"},
}
NATIVE_SYMBOLS = {"ETH"}          # an ERC-20 called "ETH" is never the real ether
# Cyrillic and Greek letters that look like Latin ones (used in fake symbols such as "WВТC").
HOMOGLYPHS = str.maketrans("АВЕКМНОРСТУХаеорсухΑΒΕΗΙΚΜΝΟΡΤΥΧοѕіј", "ABEKMHOPCTYXaeopcyxABEHIKMNOPTYXosij")
PREFIX, SUFFIX = 4, 4             # wallets usually show 0x + 4 chars ... 4 chars


class Blockscout:
    def __init__(self, chain: int, key: str | None):
        self.chain, self.key = chain, key
        self.base = f"https://api.blockscout.com/{chain}" if key else PUBLIC.get(chain)
        if not self.base:
            sys.exit(f"No public Blockscout instance for chain {chain}; set BLOCKSCOUT_API_KEY")
        self.calls = 0

    def explorer(self, kind: str, value: str) -> str:
        host = PUBLIC.get(self.chain, f"https://eth.blockscout.com")
        return f"{host}/{kind}/{value}"

    def get(self, path: str, params: dict | None = None) -> dict:
        # The key goes in a header, never in the URL, so it cannot leak into logs or error messages.
        headers = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        for attempt in range(4):
            r = requests.get(f"{self.base}/api/v2{path}", params=params or {}, headers=headers, timeout=30)
            self.calls += 1
            if r.status_code == 429:
                time.sleep(1.5 * (attempt + 1))
                continue
            if r.status_code == 402:
                sys.exit(f"Blockscout: {r.json().get('error', 'payment required')} (chain {self.chain}). "
                         "Free PRO keys cover e.g. Ethereum (1), Optimism (10), Arbitrum (42161), Gnosis (100).")
            if not r.ok:
                sys.exit(f"Blockscout API error {r.status_code} for {path}")
            return r.json()
        sys.exit("Blockscout API: rate limit, try again later")

    def pages(self, path: str, params: dict, max_pages: int):
        params = dict(params)
        for _ in range(max_pages):
            data = self.get(path, params)
            yield from data.get("items", [])
            nxt = data.get("next_page_params")
            if not nxt:
                break
            params.update(nxt)
            time.sleep(0.25)   # free tier: 5 requests per second


def short(a: str) -> str:
    return f"{a[:2 + PREFIX]}…{a[-SUFFIX:]}"


def look_key(a: str) -> str:
    a = a.lower()
    return a[2:2 + PREFIX] + ":" + a[-SUFFIX:]


def ascii_symbol(sym: str) -> str:
    return unicodedata.normalize("NFKC", sym or "").translate(HOMOGLYPHS).upper()


def analyse(bs: Blockscout, address: str, max_pages: int, intended: str | None) -> dict:
    me = address.lower()
    info = bs.get(f"/addresses/{address}")
    transfers = list(bs.pages(f"/addresses/{address}/token-transfers", {"type": "ERC-20"}, max_pages))
    txs = list(bs.pages(f"/addresses/{address}/transactions", {}, max(1, max_pages // 2)))

    # counterparties: who this wallet really sent value to / received from
    cp = defaultdict(lambda: {"in": 0, "out": 0, "real_out": 0, "first": None, "last": None, "tags": set(), "scam": False})
    def touch(other: dict, direction: str, ts: str, real: bool):
        h = other["hash"].lower()
        if h == me or int(h, 16) == 0:
            return
        c = cp[h]
        c[direction] += 1
        if direction == "out" and real:
            c["real_out"] += 1
        c["first"] = min(filter(None, [c["first"], ts]))
        c["last"] = max(filter(None, [c["last"], ts]))
        c["scam"] |= bool(other.get("is_scam"))
        for t in (other.get("metadata") or {}).get("tags", []) or []:
            c["tags"].add(t.get("name"))
        c["hash"] = other["hash"]

    findings = []
    fake_tokens = {}
    for t in transfers:
        tok = t.get("token") or {}
        sym, addr = tok.get("symbol") or "", (tok.get("address_hash") or tok.get("address") or "").lower()
        value = int((t.get("total") or {}).get("value") or 0)
        canon = CANONICAL.get(bs.chain, {})
        norm = ascii_symbol(sym)
        reasons = []
        if sym != sym.encode("ascii", "ignore").decode() and norm in set(canon) | NATIVE_SYMBOLS:
            reasons.append(f"symbol \"{sym}\" uses non-Latin look-alike letters to imitate {norm}")
        if norm in canon and addr != canon[norm]:
            reasons.append(f"not the real {norm} contract ({short(canon[norm])})")
        if norm in NATIVE_SYMBOLS:
            reasons.append("an ERC-20 named ETH: real ether is not a token")
        if tok.get("reputation") not in (None, "ok") or tok.get("is_scam"):
            reasons.append(f"Blockscout token reputation: {tok.get('reputation')}")
        fake = bool(reasons)
        if fake:
            fake_tokens[addr] = {"symbol": sym, "address": addr, "reasons": reasons, "link": bs.explorer("token", addr)}
        frm, to = t["from"], t["to"]
        out = frm["hash"].lower() == me
        real = value > 0 and not fake
        touch(to if out else frm, "out" if out else "in", t.get("timestamp"), real)
        if fake or value == 0:
            findings.append({"type": "fake_token_transfer" if fake else "zero_value_transfer",
                             "tx": t["transaction_hash"], "time": t.get("timestamp"), "token": sym,
                             "token_address": addr, "from": frm["hash"], "to": to["hash"], "value": str(value),
                             "outgoing": out, "reasons": reasons, "link": bs.explorer("tx", t["transaction_hash"])})
    for x in txs:
        if not x.get("to"):
            continue
        out = x["from"]["hash"].lower() == me
        touch(x["to"] if out else x["from"], "out" if out else "in", x.get("timestamp"), int(x.get("value") or 0) > 0)

    # spoofed "outgoing" transfers: the wallet appears as sender, but someone else signed the transaction
    for f in findings:
        if f["outgoing"]:
            tx = bs.get(f"/transactions/{f['tx']}")
            f["initiator"] = tx["from"]["hash"]
            f["spoofed"] = tx["from"]["hash"].lower() != me

    # addresses planted by an attacker: they entered the history through a fake-token, zero-value or spoofed transfer
    planted = {}
    for f in findings:
        other = (f["to"] if f["outgoing"] else f["from"]).lower()
        if other != me and int(other, 16) != 0:
            planted.setdefault(other, f["time"])

    # lookalike clusters: different addresses with the same visible prefix and suffix
    groups = defaultdict(list)
    for h, c in cp.items():
        groups[look_key(h)].append(h)
    # addresses that copy THIS wallet's own visible prefix/suffix: they impersonate it to people who pay it
    own = look_key(me)
    impersonators = [{"address": cp[h]["hash"], "first_seen": cp[h]["first"], "link": bs.explorer("address", cp[h]["hash"])}
                     for h in sorted(groups.pop(own, []), key=lambda h: cp[h]["first"] or "")]
    clusters = []
    for key, members in groups.items():
        if len(members) < 2:
            continue
        clean = sorted((h for h in members if h not in planted), key=lambda h: cp[h]["first"] or "")
        genuine = clean[0] if clean else None   # earliest counterparty that was not planted
        suspects = [h for h in members if h != genuine]
        clusters.append({"pattern": short(cp[members[0]]["hash"]),
                         "genuine_guess": cp[genuine]["hash"] if genuine else None,
                         "lookalikes": [{"address": cp[h]["hash"], "first_seen": cp[h]["first"], "planted_at": planted.get(h),
                                         "real_value_sent_to_it": cp[h]["real_out"], "link": bs.explorer("address", cp[h]["hash"])}
                                        for h in sorted(suspects, key=lambda h: cp[h]["first"] or "")],
                         "losses": [cp[h]["hash"] for h in suspects if h in planted and cp[h]["real_out"] > 0]})
    # funds sent to a planted address even without a visible twin (the genuine one may be outside the scanned range)
    lone_losses = [cp[h]["hash"] for h in planted if h in cp and cp[h]["real_out"] > 0
                   and not any(cp[h]["hash"] in c["losses"] for c in clusters)]

    # check an intended recipient before sending
    recipient = None
    if intended:
        il = intended.lower()
        twins = [cp[h]["hash"] for h in groups.get(look_key(il), []) if h != il]
        rinfo = bs.get(f"/addresses/{intended}")
        recipient = {"address": intended, "known_counterparty": il in cp, "lookalike_of": twins,
                     "is_scam": bool(rinfo.get("is_scam")), "is_contract": rinfo.get("is_contract"),
                     "tags": [t.get("name") for t in (rinfo.get("metadata") or {}).get("tags", []) or []],
                     "verdict": "OK" if il in cp else "NEW"}
        reasons = []
        if rinfo.get("is_scam"):
            reasons.append("Blockscout flags this address as scam")
        if il in planted:
            reasons.append(f"it entered your history through a fake/zero/spoofed transfer ({planted[il][:10]})")
        if twins and il not in cp:
            reasons.append("it copies the visible prefix/suffix of an address you used, but you never used this one")
        if reasons:
            recipient["verdict"] = "STOP"
        recipient["reasons"] = reasons

    spoofed = [f for f in findings if f.get("spoofed")]
    risk = "HIGH" if any(c["losses"] for c in clusters) or lone_losses else ("MEDIUM" if clusters or spoofed or impersonators else ("LOW" if findings else "NONE"))
    return {"address": info.get("hash", address), "chain_id": bs.chain, "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "risk": risk, "scanned": {"token_transfers": len(transfers), "transactions": len(txs), "api_calls": bs.calls},
            "address_info": {"is_contract": info.get("is_contract"), "is_scam": info.get("is_scam"), "ens": info.get("ens_domain_name"),
                             "tags": [t.get("name") for t in (info.get("metadata") or {}).get("tags", []) or []]},
            "lookalike_clusters": clusters, "losses_to_planted": lone_losses, "impersonators_of_this_wallet": impersonators, "fake_tokens": list(fake_tokens.values()), "spoofed_transfers": spoofed,
            "suspicious_transfers": findings, "recipient_check": recipient,
            "explorer": bs.explorer("address", info.get("hash", address))}


def to_markdown(r: dict) -> str:
    icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "NONE": "🟢"}[r["risk"]]
    L = [f"# Address poisoning report: `{r['address']}`", "",
         f"**Risk: {icon} {r['risk']}** · chain {r['chain_id']} · {r['generated']} · [Blockscout]({r['explorer']})", "",
         f"Scanned {r['scanned']['token_transfers']} token transfers and {r['scanned']['transactions']} transactions "
         f"({r['scanned']['api_calls']} API calls).", ""]
    rc = r.get("recipient_check")
    if rc:
        L += ["## Recipient check", f"- `{rc['address']}` → **{rc['verdict']}**"]
        L += [f"  - {x}" for x in rc.get("reasons", [])]
        if rc["lookalike_of"]:
            L.append(f"- ⚠️ Same visible pattern as: {', '.join('`'+a+'`' for a in rc['lookalike_of'])}")
        L.append("")
    L.append("## Lookalike addresses (same first and last characters)")
    if not r["lookalike_clusters"]:
        L.append("None found.")
    for c in r["lookalike_clusters"]:
        g = f"probable genuine `{c['genuine_guess']}`" if c["genuine_guess"] else "genuine address not in the scanned history"
        L.append(f"- Pattern **{c['pattern']}**: {g}")
        for la in c["lookalikes"]:
            lost = " 💸 **real funds were sent here**" if la["real_value_sent_to_it"] and la["planted_at"] else ""
            how = f", planted {la['planted_at']}" if la["planted_at"] else ""
            L.append(f"  - lookalike [`{la['address']}`]({la['link']}) first seen {la['first_seen']}{how}{lost}")
    L += ["", "## Addresses impersonating this wallet (same visible prefix/suffix as the wallet itself)"]
    L += [f"- [`{i['address']}`]({i['link']}) first seen {i['first_seen']}" for i in r["impersonators_of_this_wallet"]] or ["None found."]
    L += ["", "## Fake tokens"]
    L += [f"- [{f['symbol']}]({f['link']}) `{f['address']}`: {'; '.join(f['reasons'])}" for f in r["fake_tokens"]] or ["None found."]
    L += ["", "## Transfers the wallet did not sign (spoofed history)"]
    L += [f"- [{s['time']}]({s['link']}) {s['token']} → `{s['to']}`, signed by `{s['initiator']}`" for s in r["spoofed_transfers"]] or ["None found."]
    L += ["", "---", "How it works: lookalike addresses share the visible prefix/suffix that wallets display; poisoners plant them in the "
          "history with zero-value or fake-token transfers so the victim copies the wrong address. Data: Blockscout API."]
    return "\n".join(L) + "\n"


def load_env(path: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
    """Read KEY=VALUE lines from .env next to this script (keeps the API key out of the code and the repo)."""
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"'))


def main():
    load_env()
    ap = argparse.ArgumentParser(description="Detect address-poisoning traces with Blockscout")
    ap.add_argument("address")
    ap.add_argument("--chain", type=int, default=1)
    ap.add_argument("--to", dest="intended")
    ap.add_argument("--pages", type=int, default=10, help="50 transfers per page")
    ap.add_argument("--out", default="reports")
    a = ap.parse_args()
    bs = Blockscout(a.chain, os.getenv("BLOCKSCOUT_API_KEY"))
    r = analyse(bs, a.address, a.pages, a.intended)
    os.makedirs(a.out, exist_ok=True)
    base = os.path.join(a.out, f"{a.chain}_{r['address']}")
    json.dump(r, open(base + ".json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    open(base + ".md", "w", encoding="utf-8").write(to_markdown(r))
    print(f"Risk {r['risk']}: {len(r['lookalike_clusters'])} lookalike groups, {len(r['impersonators_of_this_wallet'])} impersonators, {len(r['fake_tokens'])} fake tokens, "
          f"{len(r['spoofed_transfers'])} spoofed transfers. Report: {base}.md")


if __name__ == "__main__":
    main()

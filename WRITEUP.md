# Sprint 1 write-up: Scam Address Checker

## Problem
Address poisoning is one of the most common ways people lose crypto without any hack: an attacker generates an address with the same first and last characters as one you use, plants it in your history with zero-value or fake-token transfers, and waits for you to copy it. In May 2024 one wallet sent 1,155 WBTC (about $68M at the time) to such a look-alike. Explorers and wallets still show these planted entries next to real ones.

## What we built
A command-line checker that turns Blockscout data into a clear verdict for a wallet:
- **Look-alike groups**: addresses in the history that share the visible prefix/suffix.
- **Planted addresses**: look-alikes that entered the history through fake tokens, zero-value or spoofed transfers.
- **Fake tokens**: homoglyph symbols (`WВТC` with Cyrillic letters), copies of major tokens at non-canonical contracts, ERC-20s named `ETH`, Blockscout scam reputation.
- **Spoofed history**: transfers that show the wallet as sender but were signed by someone else.
- **Losses**: real value sent to a planted address.
- **Impersonators**: addresses that copy the wallet's own prefix/suffix.
- **Recipient check** (`--to`): returns STOP before you send to a look-alike.
Each finding links to Blockscout Explorer as evidence. Output: Markdown report + JSON.

## How Blockscout is used (core, not a side integration)
All data comes from the Blockscout PRO API REST v2: address info and labels, paginated ERC-20 token transfers with token reputation, native transactions, and per-transaction signer lookup for suspicious transfers. One key, chain selected per run (tested on Ethereum, Optimism; Arbitrum and Gnosis also available on the free plan).

## Results
- Real 2024 case (`0x1E22…8FD5`): **HIGH**. Finds the fake `WВТC`, two planted look-alikes `0xd9A1…3a91`, three spoofed transfers, the loss, and STOP for the attacker address. About 13 API calls, under 10 seconds.
- `vitalik.eth` on Ethereum: **NONE** (no false positives on a very busy wallet).
- `vitalik.eth` on Optimism: **MEDIUM**: two addresses imitating `0xd8dA…6045` itself.

## Plan for Sprint 2
1. Web UI: paste an address, get the verdict and evidence; "check before sending" box.
2. Watch mode with Telegram alerts when a new look-alike is planted.
3. Cross-chain attacker view (same planting contract or signer across chains).
4. Tests on a labelled set of known poisoning cases to measure precision.

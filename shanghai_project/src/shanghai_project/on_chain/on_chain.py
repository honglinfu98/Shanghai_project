 
 
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Produce ONE NDJSON line for a tx:
- eventLogs: ordered exactly as in eth_getTransactionReceipt.logs (logIndex order)
  * Decode six event types only: Unshield, Nullified, Withdrawal, Transact, Shield, and ALL ERC-20 Transfer
  * topics represented as an object: {"signature":..., "from":..., "to":..., "src":...}
  * data represented as an object with decoded non-indexed fields
- internalValueCalls: ordered by real call order from debug_traceTransaction (callTracer),
  * include ONLY non-top frames with value > 0 (wei): {"from","to","value"}
 
Output file (single-tx mode): ../data/<txhash>.ndjson  (directory auto-created)
Output file (range modes):   ../data/railgun-relay-<mode>-<from>-<to>.ndjson
  - mode ∈ {default,test,v2}; lines ordered from older to newer (by block,txIndex).
Cached tx list file:           ../data/railgun-relay-<mode>-<from>-<to>-txhashes.json
 
Usage:
  python debug_traceTransaction.py scan test   # scan [23188417,23195768] and cache tx hashes (JSON)
  python debug_traceTransaction.py scan v2     # scan [16076984,23195768] and cache tx hashes (JSON)
  python debug_traceTransaction.py build test  # build NDJSON from cached test list
  python debug_traceTransaction.py build v2    # build NDJSON from cached v2 list
  python debug_traceTransaction.py build <txhash>  # build ONE tx NDJSON
 
Notes:
  - No default ranges: you must specify test or v2 for range operations.
  - No default tx: single-transaction mode requires an explicit <txhash> with `build`.
  - SCAN uses address-only filtering (Relay contract) for candidate discovery; BUILD still decodes six events (adds ERC-20 Transfer, Withdrawal).
  - BUILD uses a shared HTTP session (Keep-Alive) and a small thread pool (env BUILD_MAX_WORKERS, default 6) to reduce wall time; CU unchanged.
  - RPC backs off on HTTP 429/Rate-Limit using Retry-After/exponential backoff to avoid throttling bursts.
  - `scan` and `build` are separate steps (no combined `scan build`).
 
Env:
  ALCHEMY_URL=https://eth-mainnet.g.alchemy.com/v2/<YOUR_KEY>
 
Refs:
- Receipt logs ordering / logIndex semantics.  [oai_citation:4‡QuickNode](https://www.quicknode.com/docs/ethereum/eth_getTransactionReceipt?utm_source=chatgpt.com) [oai_citation:5‡GitHub](https://github.com/ethereum/go-ethereum/issues/2028?utm_source=chatgpt.com)
- debug_traceTransaction / callTracer for call-order tracing.  [oai_citation:6‡Alchemy](https://www.alchemy.com/docs/node/debug-api/debug-api-endpoints/debug-trace-transaction?utm_source=chatgpt.com) [oai_citation:7‡go-ethereum](https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers?utm_source=chatgpt.com)
- ERC-20 Transfer signature & topic layout.  [oai_citation:8‡developers.avacloud.io](https://developers.avacloud.io/webhooks-api/erc20-transfers?utm_source=chatgpt.com) [oai_citation:9‡docs.goldsky.com](https://docs.goldsky.com/mirror/guides/token-transfers/ERC-20-transfers?utm_source=chatgpt.com)
"""
 
import os
import sys
import json
import requests
import time
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
from requests.adapters import HTTPAdapter
import threading
from concurrent.futures import ThreadPoolExecutor
 
from eth_abi import decode as abi_decode
from eth_utils import to_checksum_address
 
ALCHEMY_URL = os.getenv(
    "ALCHEMY_URL",
    "YOUR_API",
)
 
# --------- HTTP session (Keep-Alive, pooling) ---------
_SESSION = requests.Session()
_ADAPTER = HTTPAdapter(pool_connections=32, pool_maxsize=32)
_SESSION.mount("http://", _ADAPTER)
_SESSION.mount("https://", _ADAPTER)
_POST_LOCK = threading.Lock()  # serialize .post when needed
 
# --------- Target contract and default ranges ---------
TARGET_CONTRACT = "0xFA7093CDD9EE6932B4Eb2c9E1Cde7cE00B1fA4B9"  # Railgun: Relay
TEST_FROM_BLOCK = 23188417  #Aug-21-2025 08:59:59 AM +UTC
TEST_TO_BLOCK   = 23195768  #Aug-22-2025 09:38:11 AM +UTC
V2_FROM_BLOCK   = 16076984  #Nov-29-2022 04:57:35 PM +UTC
V2_TO_BLOCK     = 23042522  #Aug-01-2025 12:01:47 AM UTC
 
# --- Event signatures (topics[0]) ---
SIG_TRANSFER   = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"  # Transfer(address,address,uint256)
SIG_WITHDRAWAL = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65"  # Withdrawal(address,uint256)
SIG_UNSHIELD   = "0xd93cf895c7d5b2cd7dc7a098b678b3089f37d91f48d9b83a0800a91cbdf05284"  # Unshield(address,(uint8,address,uint256),uint256,uint256)
SIG_NULLIFIED  = "0x781745c57906dc2f175fec80a9c691744c91c48a34a83672c41c2604774eb11f"  # Nullified(uint16,bytes32[])
SIG_TRANSACT = "0x56a618cda1e34057b7f849a5792f6c8587a2dbe11c83d0254e72cb3daffda7d1"  # Transact(uint256,uint256,bytes32[],(bytes32[4],bytes32,bytes32,bytes,bytes)[])
SIG_SHIELD    = "0x3a5b9dc26075a3801a6ddccf95fec485bb7500a91b44cec1add984c21ee6db3b"  # Shield(uint256,uint256,(bytes32,(uint8,address,uint256),uint120)[],(bytes32[3],bytes32)[],uint256[])
 
BUILD_SIGS = {SIG_TRANSFER, SIG_WITHDRAWAL, SIG_UNSHIELD, SIG_NULLIFIED, SIG_TRANSACT, SIG_SHIELD}
 
# ---------- JSON-RPC ----------
def rpc(method: str, params: list) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    # Exponential backoff on 429 / transient network errors (does NOT change CU)
    backoff = 0.5
    for _ in range(6):
        try:
            with _POST_LOCK:
                r = _SESSION.post(ALCHEMY_URL, json=payload, timeout=120)
            if r.status_code == 429:
                ra = r.headers.get("Retry-After")
                delay = float(ra) if ra and ra.isdigit() else backoff
                time.sleep(delay)
                backoff = min(backoff * 2, 8.0)
                continue
            r.raise_for_status()
            resp = r.json()
            if "error" in resp:
                msg = str(resp.get("error", "")).lower()
                if any(x in msg for x in ("rate limit", "too many", "capacity", "timeout")):
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 8.0)
                    continue
                raise RuntimeError(f"RPC error: {resp['error']}")
            return resp["result"]
        except requests.exceptions.RequestException:
            time.sleep(backoff)
            backoff = min(backoff * 2, 8.0)
    raise RuntimeError(f"RPC request failed after retries: {method}")
 
# ---------- Utils ----------
def hex_to_int(h: Optional[str]) -> int:
    if not h or h == "0x":
        return 0
    return int(h, 16)
 
def is_nonzero_hex(h: Optional[str]) -> bool:
    try:
        return hex_to_int(h) > 0
    except Exception:
        return False
 
def to_block_hex(n: int) -> str:
    return hex(int(n))
 
def topic_to_address(topic_hex: str) -> str:
    """topics[i] are 32-byte values; addresses are right-aligned (last 20 bytes)."""
    clean = (topic_hex or "").lower().replace("0x", "")
    addr = "0x" + clean[-40:]
    try:
        return to_checksum_address(addr)
    except Exception:
        return addr
 
def checksum(addr_hex: Optional[str]) -> str:
    if not addr_hex:
        return "0x0000000000000000000000000000000000000000"
    try:
        return to_checksum_address(addr_hex)
    except Exception:
        return addr_hex
 
 
def hx(b: Optional[bytes]) -> str:
    """Bytes-like -> 0x-prefixed lowercase hex; None/empty -> "0x"."""
    if not b:
        return "0x"
    try:
        return "0x" + (b.hex() if hasattr(b, "hex") else bytes(b).hex())
    except Exception:
        return "0x"
 
# ---------- Progress bar helpers (single-line, with rate & ETA) ----------
_last_render_time: float = 0.0
 
def _fmt_hms(seconds: float) -> str:
    try:
        s = int(max(0, seconds))
        h, rem = divmod(s, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h:d}h{m:02d}m{s:02d}s"
        if m:
            return f"{m:d}m{s:02d}s"
        return f"{s:d}s"
    except Exception:
        return "--"
 
def render_progress(current: int, total: int, start_time: float, *, prefix: str = "", min_interval: float = 0.1) -> None:
    """Render a single-line progress bar with rate and ETA. Overwrites the same console line.
    Only updates if at least `min_interval` seconds have elapsed since the last render.
    """
    global _last_render_time
    now = time.time()
    if now - _last_render_time < min_interval and current < total:
        return
    _last_render_time = now
 
    current = max(0, min(current, total))
    elapsed = max(1e-9, now - start_time)
    rate = current / elapsed
    remain = max(0.0, (total - current) / rate) if rate > 0 else 0.0
 
    # Determine bar width from terminal size
    try:
        width = shutil.get_terminal_size((100, 20)).columns
    except Exception:
        width = 100
 
    # Build bar
    pct = (current / total * 100.0) if total > 0 else 0.0
    bar_width = max(10, min(40, width - 60))
    filled = int(round(bar_width * (current / total))) if total > 0 else 0
    bar = "█" * filled + "·" * (bar_width - filled)
 
    line = (
        f"{prefix:>6} |[{bar}] {pct:6.2f}% "
        f"{current:>7d}/{total:<7d} | {rate:6.2f}/s | ETA {_fmt_hms(remain)}"
    )
 
    # Ensure we don't wrap lines
    if len(line) >= width:
        line = line[: width - 1]
 
    sys.stdout.write("\r" + line)
    sys.stdout.flush()
 
def finish_progress() -> None:
    sys.stdout.write("\n")
    sys.stdout.flush()
 
# ---------- Log scanning helpers ----------
def fetch_logs_for_range(from_block: int, to_block: int, step: int = 2000) -> List[Dict[str, Any]]:
    """
    Fetch logs for TARGET_CONTRACT within [from_block, to_block], chunked to avoid provider limits.
    SCAN phase: address-only filter (no topic0); auto-halves step on timeout/oversize until min_step.
    """
    all_logs: List[Dict[str, Any]] = []
    total_blocks = max(0, to_block - from_block + 1)
    processed_blocks = 0
    start_time = time.time()
 
    min_step = 128  # safety floor for problematic ranges
    cur_step = max(min_step, int(step))
    base_step = cur_step
 
    start = from_block
    while start <= to_block:
        end = min(start + cur_step - 1, to_block)
        flt = {
            "fromBlock": to_block_hex(start),
            "toBlock": to_block_hex(end),
            "address": TARGET_CONTRACT,
        }
        try:
            batch = rpc("eth_getLogs", [flt])
            all_logs.extend(batch or [])
 
            # update progress only when a chunk succeeds
            processed_blocks = min(total_blocks, end - from_block + 1)
            render_progress(processed_blocks, total_blocks, start_time, prefix="scan")
 
            # advance the window; gently grow step back towards base on success
            start = end + 1
            if cur_step < base_step:
                cur_step = min(base_step, cur_step * 2)
            continue
        except Exception as e:
            msg = str(e).lower()
            retryable = (
                "timeout" in msg
                or "timed out" in msg
                or "rate limit" in msg
                or "too many" in msg
                or "limit" in msg
                or "response size" in msg
                or "log response" in msg
            )
            if retryable and cur_step > min_step:
                # halve and retry the same [start, ...] chunk
                cur_step = max(min_step, cur_step // 2)
                continue
            if retryable and cur_step == min_step:
                # one brief pause at floor, then final try
                time.sleep(1.0)
                try:
                    batch = rpc("eth_getLogs", [flt])
                    all_logs.extend(batch or [])
                    processed_blocks = min(total_blocks, end - from_block + 1)
                    render_progress(processed_blocks, total_blocks, start_time, prefix="scan")
                    start = end + 1
                    continue
                except Exception as e2:
                    raise RuntimeError(f"eth_getLogs failed at [{start},{end}] with min_step={min_step}: {e2}") from e2
            # non-retryable: bubble up
            raise
 
    finish_progress()
    return all_logs
 
def candidate_transactions(from_block: int, to_block: int) -> List[str]:
    """Return unique tx hashes touching TARGET_CONTRACT with wanted events, sorted by (blockNumber, txIndex)."""
    logs = fetch_logs_for_range(from_block, to_block)
    best: Dict[str, tuple] = {}
    for lg in logs:
        txh = (lg.get("transactionHash") or "").lower()
        if not txh:
            continue
        bn = hex_to_int(lg.get("blockNumber"))
        tix = hex_to_int(lg.get("transactionIndex"))
        if txh not in best or (bn, tix) < best[txh]:
            best[txh] = (bn, tix)
    # sort by block, txIndex ascending
    return [h for (h, _) in sorted(best.items(), key=lambda kv: kv[1])]
 
# ---------- Tx-hash list caching ----------
 
def hashlist_path(mode: str, from_block: int, to_block: int) -> Path:
    out_dir = (Path(__file__).resolve().parent / ".." / "data").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"railgun-relay-{mode}-{from_block}-{to_block}-txhashes.json"
 
def save_tx_hashes(path: Path, hashes: List[str], *, mode: str = "default", from_block: int = 0, to_block: int = 0) -> None:
    payload = {
        "mode": mode,
        "fromBlock": from_block,
        "toBlock": to_block,
        "count": len(hashes),
        "hashes": [h.lower() for h in hashes],
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
 
def load_tx_hashes(path: Path) -> List[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        try:
            payload = json.load(f)
            hashes = payload.get("hashes")
            if isinstance(hashes, list):
                return [str(h).lower() for h in hashes if isinstance(h, str) and h]
        except Exception:
            return []
    return []
 
# ---------- Event decoding (to desired schema) ----------
def decode_event_to_obj(log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    topics: List[str] = log.get("topics", []) or []
    if not topics:
        return None
    sig = topics[0].lower()
    if sig not in BUILD_SIGS:
        return None
 
    address = checksum(log.get("address"))
    data_hex = log.get("data", "0x")
    data_bytes = bytes.fromhex(data_hex[2:]) if data_hex and data_hex != "0x" else b""
 
    obj = {
        "address": address,
        "eventName": "",
        "topics": {},
        "data": {},
    }
    # topics.signature always included
    obj["topics"]["signature"] = sig
 
    if sig == SIG_TRANSFER:
        # Transfer(address indexed from, address indexed to, uint256 value)
        obj["eventName"] = "Transfer"
        if len(topics) >= 2:
            obj["topics"]["from"] = topic_to_address(topics[1])
        if len(topics) >= 3:
            obj["topics"]["to"] = topic_to_address(topics[2])
        if data_bytes:
            (value,) = abi_decode(["uint256"], data_bytes)
            obj["data"]["value"] = str(value)
        else:
            obj["data"]["value"] = "0"
        # If ERC-721 (topics[3] holds tokenId), include it
        if len(topics) >= 4:
            try:
                obj["data"]["tokenId"] = str(int(topics[3], 16))
            except Exception:
                pass
 
    elif sig == SIG_WITHDRAWAL:
        # Withdrawal(address indexed src, uint256 wad)
        obj["eventName"] = "Withdrawal"
        if len(topics) >= 2:
            obj["topics"]["src"] = topic_to_address(topics[1])
        if data_bytes:
            try:
                (wad,) = abi_decode(["uint256"], data_bytes)
                obj["data"]["wad"] = str(wad)
            except Exception:
                # leave data empty if decode fails
                pass
        else:
            obj["data"]["wad"] = "0"
 
    elif sig == SIG_UNSHIELD:
        # Unshield(address to, (uint8,address,uint256) token, uint256 amount, uint256 fee)
        obj["eventName"] = "Unshield"
        if data_bytes:
            try:
                to_addr, token_tuple, amount, fee = abi_decode(
                    ["address", "(uint8,address,uint256)", "uint256", "uint256"], data_bytes
                )
                token_type, token_addr, token_id = token_tuple
                obj["data"] = {
                    "to": checksum(to_addr),
                    "token": {
                        "type": str(token_type),
                        "address": checksum(token_addr),
                        "id": str(token_id),
                    },
                    "amount": str(amount),
                    "fee": str(fee),
                }
            except Exception:
                pass
 
    elif sig == SIG_NULLIFIED:
        # Nullified(uint16 treeNumber, bytes32[] nullifier)
        obj["eventName"] = "Nullified"
        if data_bytes:
            try:
                tree_num, nullifiers = abi_decode(["uint16", "bytes32[]"], data_bytes)
                obj["data"] = {
                    "treeNumber": str(tree_num),
                    "nullifier": [hx(n) for n in (nullifiers or [])],
                }
            except Exception:
                pass
 
    elif sig == SIG_TRANSACT:
        # Transact(uint256 treeNumber, uint256 startPosition, bytes32[] hash, (bytes32[4],bytes32,bytes32,bytes,bytes)[] ciphertext)
        obj["eventName"] = "Transact"
        if data_bytes:
            try:
                tree_num, start_pos, hash_arr, ctexts = abi_decode(
                    [
                        "uint256",
                        "uint256",
                        "bytes32[]",
                        "(bytes32[4],bytes32,bytes32,bytes,bytes)[]",
                    ],
                    data_bytes,
                )
                obj["data"] = {
                    "treeNumber": str(tree_num),
                    "startPosition": str(start_pos),
                    "hash": [hx(h) for h in (hash_arr or [])],
                    "ciphertext": [
                        [
                            [hx(b) for b in (c0 or [])],
                            hx(c1),
                            hx(c2),
                            hx(c3),
                            hx(c4),
                        ]
                        for (c0, c1, c2, c3, c4) in (ctexts or [])
                    ],
                }
            except Exception:
                pass
 
    elif sig == SIG_SHIELD:
        # Shield(uint256 treeNumber, uint256 startPosition, (bytes32,(uint8,address,uint256),uint120)[] commitments, (bytes32[3],bytes32)[] shieldCiphertext, uint256[] fees)
        obj["eventName"] = "Shield"
        if data_bytes:
            try:
                tree_num, start_pos, commitments, shield_ct, fees = abi_decode(
                    [
                        "uint256",
                        "uint256",
                        "(bytes32,(uint8,address,uint256),uint120)[]",
                        "(bytes32[3],bytes32)[]",
                        "uint256[]",
                    ],
                    data_bytes,
                )
                obj["data"] = {
                    "treeNumber": str(tree_num),
                    "startPosition": str(start_pos),
                    "commitments": [
                        [
                            hx(h),
                            [str(t_type), checksum(t_addr), str(t_id)],
                            str(val_u120),
                        ]
                        for (h, (t_type, t_addr, t_id), val_u120) in (commitments or [])
                    ],
                    "shieldCiphertext": [
                        [
                            [hx(b) for b in (s0 or [])],
                            hx(s1),
                        ]
                        for (s0, s1) in (shield_ct or [])
                    ],
                    "fees": [str(f) for f in (fees or [])],
                }
            except Exception:
                pass
 
    return obj
 
# ---------- Call tracer flattening (value>0 internal calls only) ----------
def walk_calls_value_transfers(node: Dict[str, Any], depth: int, acc: List[Dict[str, Any]]):
    """
    DFS in call order. We only record non-top frames with value>0 (native ETH).
    callTracer preserves call order; we ignore logs here (events come from receipt).
    """
    if depth > 0 and is_nonzero_hex(node.get("value")):
        acc.append({
            "from": checksum(node.get("from")),
            "to": checksum(node.get("to")),
            "value": str(hex_to_int(node.get("value"))),  # wei
        })
    for child in node.get("calls", []) or []:
        walk_calls_value_transfers(child, depth + 1, acc)
 
def trace_calltree(txh: str) -> Dict[str, Any]:
    # callTracer is sufficient; we don't need withLog since events come from receipt
    cfg = {"tracer": "callTracer"}  # per Geth built-in tracer docs
    return rpc("debug_traceTransaction", [txh, cfg])
 
# ---------- Single-transaction summariser ----------
def build_tx_summary(txh: str) -> Dict[str, Any]:
    receipt = rpc("eth_getTransactionReceipt", [txh])  # logs already in order
 
    block_number = hex_to_int(receipt.get("blockNumber"))
    # Use receipt fields for from/to to save one RPC call
    from_addr    = checksum(receipt.get("from"))
    to_addr      = checksum(receipt.get("to"))
 
    # eventLogs: iterate receipt.logs and decode only the target event kinds
    event_logs: List[Dict[str, Any]] = []
    for lg in receipt.get("logs", []) or []:
        ev = decode_event_to_obj(lg)
        if ev is not None:
            event_logs.append(ev)
 
    # internalValueCalls: trace call tree and collect value>0 internal calls in order
    root = trace_calltree(txh)
    internal_calls: List[Dict[str, Any]] = []
    walk_calls_value_transfers(root, depth=0, acc=internal_calls)
 
    return {
        "blockNumber": block_number,
        "transactionHash": txh,
        "from": from_addr,
        "to": to_addr,
        "eventLogs": event_logs,
        "internalValueCalls": internal_calls,
    }
 
# ---------- Main ----------
def main():
    args = [a.strip() for a in sys.argv[1:]]
    if not args:
        print("Usage: scan|build (test|v2|<txhash>)\n  e.g. 'scan test', 'build test', 'build 0x..'")
        return
 
    cmd = args[0].lower()
 
    def resolve_mode(arg: str):
        if arg == "test":
            return "test", TEST_FROM_BLOCK, TEST_TO_BLOCK
        if arg == "v2":
            return "v2", V2_FROM_BLOCK, V2_TO_BLOCK
        return None, None, None
 
    if cmd == "scan":
        if len(args) < 2:
            print("scan requires a mode: test or v2")
            return
        mode, from_block, to_block = resolve_mode(args[1].lower())
        if not mode:
            print("scan requires a valid mode: test or v2")
            return
        hl_path = hashlist_path(mode, from_block, to_block)
        tx_hashes = candidate_transactions(from_block, to_block)
        # Ensure clean line after progress
        # (candidate_transactions already rendered progress from fetch_logs_for_range)
        save_tx_hashes(hl_path, tx_hashes, mode=mode, from_block=from_block, to_block=to_block)
        print("scan file:", str(hl_path))
        return
 
    if cmd == "build":
        if len(args) < 2:
            print("build requires 'test'|'v2' or a <txhash>")
            return
        arg1 = args[1]
        # Single-transaction build if txhash provided
        if arg1.startswith("0x") and len(arg1) == 66:
            txh = arg1
            obj = build_tx_summary(txh)
            out_dir = (Path(__file__).resolve().parent / ".." / "data").resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{txh}.ndjson"
            with out_path.open("w", encoding="utf-8") as f:
                f.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
            print(str(out_path))
            return
        # Range build from cached list
        mode, from_block, to_block = resolve_mode(arg1.lower())
        if not mode:
            print("build requires 'test'|'v2' or a <txhash>")
            return
        hl_path = hashlist_path(mode, from_block, to_block)
        tx_hashes = load_tx_hashes(hl_path)
        if not tx_hashes:
            print(f"Missing or empty tx-hash list: {hl_path}. Run 'scan {mode}' first.")
            return
        out_dir = (Path(__file__).resolve().parent / ".." / "data").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"railgun-relay-{mode}-{from_block}-{to_block}.ndjson"
        start_time = time.time()
        total = len(tx_hashes)
        max_workers = int(os.getenv("BUILD_MAX_WORKERS", "6"))  # conservative default to avoid 429 bursts (CU unchanged)
        with out_path.open("w", encoding="utf-8") as f:
            # executor.map preserves input order; output order unchanged; CU unchanged (still 2 RPCs/tx)
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                for i, obj in enumerate(ex.map(build_tx_summary, tx_hashes), 1):
                    f.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
                    render_progress(i, total, start_time, prefix="build")
        finish_progress()
        print("scan file:", str(hl_path))
        print("build file:", str(out_path))
        return
 
    # Unknown command
    print("Usage: scan|build (test|v2|<txhash>)\n  e.g. 'scan test', 'build test', 'build 0x..'")
    return
 
if __name__ == "__main__":
    main()
 
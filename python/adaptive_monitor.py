import asyncio, json, hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

# ── KONFİQURASİYA ─────────────────────────────────────────────────────────────
RPC_URL              = "https://eth-sepolia.g.alchemy.com/v2/0vnRc7KUEXrwkQlHasBEI"
THREAT_DETECTOR_ADDR = "0x733a81BCBF22815675e788D3e406Dc2f0cE71E8f"
HYBRID_GUARDIAN_ADDR = "0x5FC0Dbf8f4D1fE65A313354908f7ceE3110aCe78"
LOG_FILE             = Path("logs/threat_monitor.jsonl")
BLOCK_RANGE          = 9        # Alchemy Free tier: max 9 blok
POLL_INTERVAL        = 8        # saniyə
ALERT_SCORE          = 70
CRITICAL_SCORE       = 90

# ── ABI (ThreatDetector v2 ilə tam uyğun) ────────────────────────────────────
ABI = [
    {
        "name": "DDoSDetected", "type": "event", "anonymous": False,
        "inputs": [
            {"name": "actor",   "type": "address", "indexed": True},
            {"name": "count",   "type": "uint256", "indexed": False}
        ]
    },
    {
        "name": "SybilDetected", "type": "event", "anonymous": False,
        "inputs": [
            {"name": "actor",   "type": "address", "indexed": True}
        ]
    },
    {
        "name": "ReplayDetected", "type": "event", "anonymous": False,
        "inputs": [
            {"name": "nullifier", "type": "bytes32", "indexed": True},
            {"name": "actor",     "type": "address", "indexed": True}
        ]
    },
    {
        "name": "ThreatBlocked", "type": "event", "anonymous": False,
        "inputs": [
            {"name": "actor", "type": "address", "indexed": True},
            {"name": "until", "type": "uint256", "indexed": False}
        ]
    },
    {
        "name": "getSummary", "type": "function", "stateMutability": "view",
        "inputs":  [{"name": "actor", "type": "address"}],
        "outputs": [
            {"name": "score",   "type": "uint8"},
            {"name": "blocked", "type": "bool"},
            {"name": "reqs",    "type": "uint256"},
            {"name": "sybil",   "type": "bool"},
            {"name": "txCount", "type": "uint256"}
        ]
    }
]

# ── STATE ─────────────────────────────────────────────────────────────────────
@dataclass
class ActorState:
    score:         int  = 0
    ddos_count:    int  = 0
    sybil_flagged: bool = False
    replay_count:  int  = 0
    blocked:       bool = False

# ── MONITOR ───────────────────────────────────────────────────────────────────
class AdaptiveMonitor:

    def __init__(self):
        print("🔌 RPC-yə qoşulur...", flush=True)
        self.w3 = Web3(Web3.HTTPProvider(RPC_URL))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        assert self.w3.is_connected(), "❌ RPC bağlantısı yoxdur!"
        print(f"✅ Bağlandı | Blok: {self.w3.eth.block_number}", flush=True)

        self.contract = self.w3.eth.contract(
            address=self.w3.to_checksum_address(THREAT_DETECTOR_ADDR),
            abi=ABI
        )
        self.states = defaultdict(ActorState)
        LOG_FILE.parent.mkdir(exist_ok=True)

        print(f"📋 ThreatDetector : {THREAT_DETECTOR_ADDR}", flush=True)
        print(f"🛡️  HybridGuardian : {HYBRID_GUARDIAN_ADDR}", flush=True)

    # ── LOG ───────────────────────────────────────────────────────────────────
    def _log(self, actor, reason, score, delta):
        entry = {
            "ts":     datetime.utcnow().isoformat(),
            "actor":  actor,
            "reason": reason,
            "score":  score,
            "delta":  delta
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

    # ── SCORE ─────────────────────────────────────────────────────────────────
    def _add_score(self, actor, pts, reason):
        s   = self.states[actor]
        old = s.score
        s.score = min(100, old + pts)

        level = (
            "🔴 KRİTİK" if s.score >= CRITICAL_SCORE else
            "🟠 YÜKSƏK" if s.score >= ALERT_SCORE    else
            "🟡 ORTA"   if s.score >= 40             else
            "🟢 NORMAL"
        )
        print(f"  [{level}] {actor[:14]}... | {reason} | {old}→{s.score}/100", flush=True)
        self._log(actor, reason, s.score, pts)

    # ── SAFE LOG FETCH ────────────────────────────────────────────────────────
    def _get_logs(self, event, from_b, to_b):
        try:
            return event.get_logs(from_block=from_b, to_block=to_b)
        except Exception as e:
            if "block range" in str(e).lower() or "10 block" in str(e):
                pass   # Alchemy limit — normal
            else:
                print(f"  [LOG XƏTA] {event.event_name}: {e}", flush=True)
            return []

    # ── POLLING ───────────────────────────────────────────────────────────────
    async def _poll(self):
        last = self.w3.eth.block_number
        print(f"\n👁️  Polling başladı | Başlanğıc blok: {last}\n", flush=True)

        while True:
            try:
                cur = self.w3.eth.block_number
                if cur > last:
                    from_b = max(last + 1, cur - BLOCK_RANGE)
                    print(f"📦 Blok: {cur}", flush=True)

                    # DDoS
                    for e in self._get_logs(
                            self.contract.events.DDoSDetected, from_b, cur):
                        actor = e["args"]["actor"]
                        cnt   = e["args"]["count"]
                        print(f"\n🚨 [DDoS] {actor} | Sorğu: {cnt}", flush=True)
                        self.states[actor].ddos_count += 1
                        self._add_score(actor, 35, "DDoS")

                    # Sybil
                    for e in self._get_logs(
                            self.contract.events.SybilDetected, from_b, cur):
                        actor = e["args"]["actor"]
                        print(f"\n🚨 [Sybil] {actor}", flush=True)
                        self.states[actor].sybil_flagged = True
                        self._add_score(actor, 30, "Sybil")

                    # Replay
                    for e in self._get_logs(
                            self.contract.events.ReplayDetected, from_b, cur):
                        actor = e["args"]["actor"]
                        nul   = e["args"]["nullifier"].hex()
                        print(f"\n🚨 [Replay] {actor} | {nul[:16]}...", flush=True)
                        self.states[actor].replay_count += 1
                        self._add_score(actor, 50, "Replay")

                    # ThreatBlocked
                    for e in self._get_logs(
                            self.contract.events.ThreatBlocked, from_b, cur):
                        actor = e["args"]["actor"]
                        print(f"\n🔒 [BLOKLANDI] {actor}", flush=True)
                        self.states[actor].blocked = True

                    last = cur

            except Exception as e:
                print(f"[XƏTA] {e}", flush=True)

            await asyncio.sleep(POLL_INTERVAL)

    # ── DASHBOARD ─────────────────────────────────────────────────────────────
    async def _dashboard(self):
        while True:
            await asyncio.sleep(60)
            print("\n" + "═"*52, flush=True)
            print("  🛡️  ZK-Hybrid Threat Dashboard", flush=True)
            print("═"*52, flush=True)
            if not self.states:
                print("  Hələ heç bir hadisə yoxdur.", flush=True)
            else:
                for actor, s in sorted(
                    self.states.items(), key=lambda x: x[1].score, reverse=True
                ):
                    bar   = "█"*(s.score//10) + "░"*(10 - s.score//10)
                    lvl   = "🔴" if s.score>=90 else "🟠" if s.score>=70 \
                            else "🟡" if s.score>=40 else "🟢"
                    blk   = " 🔒" if s.blocked else ""
                    print(f"  {actor[:14]}... [{bar}] {s.score:3}/100 {lvl}{blk}",
                          flush=True)
                    print(f"    DDoS:{s.ddos_count} Sybil:{s.sybil_flagged}"
                          f" Replay:{s.replay_count}", flush=True)
            print("═"*52 + "\n", flush=True)

    # ── RUN ───────────────────────────────────────────────────────────────────
    async def run(self):
        print("\n" + "="*52, flush=True)
        print("  🚀 ZK-Hybrid Adaptive Monitor v3.2", flush=True)
        print("="*52 + "\n", flush=True)
        await asyncio.gather(self._poll(), self._dashboard())


# ── HELPER ────────────────────────────────────────────────────────────────────
def compute_nullifier(proof_json: dict, chain_id: int = 11155111) -> str:
    raw = json.dumps(proof_json, sort_keys=True).encode()
    raw += chain_id.to_bytes(32, "big")
    return "0x" + hashlib.sha3_256(raw).hexdigest()


if __name__ == "__main__":
    monitor = AdaptiveMonitor()
    asyncio.run(monitor.run())

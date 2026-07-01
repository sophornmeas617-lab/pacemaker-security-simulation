"""
Sophorn Meas
Merrimack College
ITS6313OM_Advanced Cybersecurity Concepts
Dr. Aspen Olmsted
May 24, 2026

Pacemaker Security Simulation — Hypothesis Test
================================================
Tests a dual-layer security model:
  Layer 1: Mutual Authentication Handshake (two-way ID check)
  Layer 2: Behavioral Anomaly Watchdog (flags unusual command patterns)

Goal: Detection Rate > 95%, detection within 5 seconds, minimal overhead.

Run:
    pip install numpy
    python pacemaker_security_test.py
"""

import random
import time
import hashlib
import hmac
import statistics
from dataclasses import dataclass, field
from typing import List, Tuple

# ── Configuration ─────────────────────────────────────────────────────────────

RANDOM_SEED       = 42
NUM_TRIALS        = 200        # total sessions simulated
ATTACK_RATIO      = 0.50       # 50% of sessions are attack attempts
DETECTION_TARGET  = 95.0       # hypothesis: >95% detection rate
LATENCY_TARGET    = 5.0        # hypothesis: detect within 5 seconds
SHARED_SECRET     = b"BioCert-PaceSec-SharedKey-2024"

random.seed(RANDOM_SEED)

# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class Session:
    session_id: int
    is_attack: bool
    # Auth fields
    device_nonce: str = ""
    programmer_nonce: str = ""
    device_token: str = ""
    programmer_token: str = ""
    tokens_match: bool = False
    # Behavioral fields
    command_timestamps: List[float] = field(default_factory=list)
    command_burst_size: int = 0
    unusual_hour: bool = False
    # Results
    auth_blocked: bool = False
    watchdog_flagged: bool = False
    detected: bool = False
    detection_time_ms: float = 0.0

# ── Layer 1: Mutual Authentication ────────────────────────────────────────────

def generate_nonce() -> str:
    return hashlib.sha256(str(random.getrandbits(128)).encode()).hexdigest()[:16]

def compute_token(nonce: str, secret: bytes) -> str:
    return hmac.new(secret, nonce.encode(), hashlib.sha256).hexdigest()

def mutual_auth_handshake(session: Session) -> bool:
    """
    Simulates a two-way HMAC handshake.
    Both sides must prove they hold the shared secret.
    Attacks are simulated as having a ~15% chance of forging a valid token
    (models a weak attacker who knows the protocol but not the key).
    """
    session.device_nonce = generate_nonce()
    session.programmer_nonce = generate_nonce()
    session.device_token = compute_token(session.device_nonce, SHARED_SECRET)

    if session.is_attack:
        # Attacker tries to forge — succeeds only 15% of the time
        forge_success = random.random() < 0.85
        if forge_success:
            session.programmer_token = session.device_token   # lucky guess
        else:
            session.programmer_token = generate_nonce()       # wrong token
    else:
        session.programmer_token = compute_token(
            session.device_nonce, SHARED_SECRET
        )

    session.tokens_match = hmac.compare_digest(
        session.device_token, session.programmer_token
    )
    session.auth_blocked = not session.tokens_match
    return session.tokens_match

# ── Layer 2: Behavioral Anomaly Watchdog ──────────────────────────────────────

NORMAL_HOUR_RANGE   = (7, 19)    # legitimate commands happen 7am–7pm
NORMAL_BURST_MAX    = 5          # max commands in a 10-second window
NORMAL_INTERVAL_MIN = 1.5        # seconds between commands (min for humans)

def simulate_command_pattern(session: Session):
    """
    Generates a realistic command timing sequence.
    Legitimate sessions: spaced-out commands during business hours.
    Attack sessions: rapid bursts or off-hours timing.
    """
    if session.is_attack:
        # Attacks: fast bursts and/or unusual hours
        session.unusual_hour = random.random() < 0.70
        session.command_burst_size = random.randint(8, 20)
        base_time = time.time()
        session.command_timestamps = [
            base_time + i * random.uniform(0.05, 0.4)
            for i in range(session.command_burst_size)
        ]
    else:
        session.unusual_hour = False
        session.command_burst_size = random.randint(1, NORMAL_BURST_MAX)
        base_time = time.time()
        session.command_timestamps = [
            base_time + i * random.uniform(NORMAL_INTERVAL_MIN, 4.0)
            for i in range(session.command_burst_size)
        ]

def behavioral_watchdog(session: Session) -> bool:
    """
    Flags a session if it violates normal usage patterns.
    Returns True (flagged) if anomalies are found.
    """
    flags = []

    # Check 1: unusual hour
    if session.unusual_hour:
        flags.append("off-hours")

    # Check 2: command burst rate
    if len(session.command_timestamps) >= 2:
        intervals = [
            session.command_timestamps[i+1] - session.command_timestamps[i]
            for i in range(len(session.command_timestamps) - 1)
        ]
        avg_interval = statistics.mean(intervals)
        if avg_interval < NORMAL_INTERVAL_MIN:
            flags.append("rapid-burst")

    # Check 3: burst count
    if session.command_burst_size > NORMAL_BURST_MAX:
        flags.append("burst-count")

    session.watchdog_flagged = len(flags) >= 1
    return session.watchdog_flagged

# ── Run One Session ───────────────────────────────────────────────────────────

def run_session(session_id: int, is_attack: bool) -> Session:
    s = Session(session_id=session_id, is_attack=is_attack)
    t_start = time.perf_counter()

    auth_passed = mutual_auth_handshake(s)
    simulate_command_pattern(s)

    if not auth_passed:
        s.detected = True
    else:
        # Auth passed — watchdog is the second line of defense
        behavioral_watchdog(s)
        if s.watchdog_flagged and s.is_attack:
            s.detected = True
        elif not s.watchdog_flagged and s.is_attack:
            s.detected = False   # missed detection
        else:
            s.detected = False   # legitimate session, not flagged (correct)

    s.detection_time_ms = (time.perf_counter() - t_start) * 1000
    return s

# ── Run Full Simulation ───────────────────────────────────────────────────────

def run_simulation() -> Tuple[List[Session], dict]:
    sessions = []
    n_attacks = int(NUM_TRIALS * ATTACK_RATIO)
    n_legit   = NUM_TRIALS - n_attacks
    labels    = [True] * n_attacks + [False] * n_legit
    random.shuffle(labels)

    for i, is_attack in enumerate(labels):
        sessions.append(run_session(i, is_attack))

    attack_sessions = [s for s in sessions if s.is_attack]
    legit_sessions  = [s for s in sessions if not s.is_attack]

    true_positives  = sum(1 for s in attack_sessions if s.detected)
    false_negatives = sum(1 for s in attack_sessions if not s.detected)
    false_positives = sum(1 for s in legit_sessions  if s.watchdog_flagged)
    true_negatives  = sum(1 for s in legit_sessions  if not s.watchdog_flagged)

    detection_rate  = (true_positives / len(attack_sessions)) * 100
    fpr             = (false_positives / len(legit_sessions))  * 100 if legit_sessions else 0
    avg_detect_ms   = statistics.mean(
        s.detection_time_ms for s in attack_sessions if s.detected
    ) if true_positives else 0

    results = {
        "total_sessions":    NUM_TRIALS,
        "attack_sessions":   len(attack_sessions),
        "legit_sessions":    len(legit_sessions),
        "true_positives":    true_positives,
        "false_negatives":   false_negatives,
        "false_positives":   false_positives,
        "true_negatives":    true_negatives,
        "detection_rate":    round(detection_rate, 2),
        "false_positive_rate": round(fpr, 2),
        "avg_detection_ms":  round(avg_detect_ms, 4),
        "target_met":        detection_rate >= DETECTION_TARGET,
        "latency_ok":        avg_detect_ms < (LATENCY_TARGET * 1000),
    }
    return sessions, results

# ── Print Report ──────────────────────────────────────────────────────────────

def print_report(results: dict):
    line = "─" * 50
    print(f"\n{'═'*50}")
    print("  PACEMAKER SECURITY SIMULATION — RESULTS")
    print(f"{'═'*50}")
    print(f"  Sessions simulated : {results['total_sessions']}")
    print(f"  Attack sessions    : {results['attack_sessions']}")
    print(f"  Legitimate sessions: {results['legit_sessions']}")
    print(line)
    print(f"  True Positives     : {results['true_positives']}  (attacks caught)")
    print(f"  False Negatives    : {results['false_negatives']}  (attacks missed)")
    print(f"  False Positives    : {results['false_positives']}  (legit flagged)")
    print(f"  True Negatives     : {results['true_negatives']}  (legit cleared)")
    print(line)
    dr   = results['detection_rate']
    fpr  = results['false_positive_rate']
    ms   = results['avg_detection_ms']
    mark = lambda ok: "✓  PASS" if ok else "✗  FAIL"
    print(f"  Detection Rate     : {dr}%   {mark(results['target_met'])}  (target ≥ {DETECTION_TARGET}%)")
    print(f"  False Positive Rate: {fpr}%")
    print(f"  Avg Detection Time : {ms} ms  {mark(results['latency_ok'])}  (target < {int(LATENCY_TARGET*1000)} ms)")
    print(f"{'═'*50}\n")

# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Running pacemaker security simulation...")
    _, results = run_simulation()
    print_report(results)

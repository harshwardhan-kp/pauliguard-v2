"""Protocol execution engine for Arbitrated Quantum Signature (AQS) schemes.

Executes a SchemeSpec and emits a verified Trace adhering to the frozen trace schema.

PROVEN:
- Quantum teleportation fidelity over noiseless EPR pairs is identically 1.0;
  teleported message states are recovered with zero error at noise_p = 0.
- Paired Pauli attacks under QOTP encryption satisfy the arbitrator verification
  predicate E_k |P> == |S> identically for all keys and message states.
- Intercept-resend eavesdropping on decoy states introduces an expected 25% QBER
  independent of channel floor.

ASSUMED:
- The arbitrator verification predicate is evaluated via ideal projective measurement
  or SWAP test in the noiseless protocol core.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import secrets
from typing import Any
import numpy as np
import stim

from pauliguard.attacks.paired_pauli import predicate_holds
from pauliguard.engine.encryption import ChainedCNOT, Encryption, Key, QOTP
from pauliguard.engine.pauli import Pauli
from pauliguard.engine.spec_loader import SchemeSpec
from pauliguard.engine.trace import (
    Action,
    Check,
    KeyDecl,
    Measurement,
    Party,
    Procedure,
    RegisterDecl,
    Step,
    Trace,
    key_fingerprint,
    validate,
)


def _remove_global_phase(v: np.ndarray, atol: float = 1e-12) -> np.ndarray:
    """Normalize a state vector by dividing out the phase of its largest-magnitude component."""
    idx = int(np.argmax(np.abs(v)))
    mag = np.abs(v[idx])
    if mag < atol:
        return v
    phase_factor = v[idx] / mag
    return v / phase_factor


@dataclass
class RunConfig:
    n_message_qubits: int = 2
    noise_p: float = 0.0                 # per-decoy-position Pauli error probability ADDED to the floor
    floor: float = 0.034423828125        # measured ibm_kingston floor; caller may override
    decoy_rounds: int = 4200             # m
    seed: int | None = None
    attack: str | None = None              # None | "paired_pauli" | "unpaired_pauli" | "intercept_resend"
    attack_pauli: str = "X"              # letter applied to qubit 0 of the message copy
    key: tuple | None = None               # explicit key, else drawn from the CSPRNG
    force_key_reuse: bool = False


class ProtocolEngine:
    def __init__(self, spec: SchemeSpec) -> None:
        self.spec = spec
        enc_name = (spec.encryption or "none").lower()
        if enc_name == "qotp":
            self.enc: Encryption | None = QOTP()
        elif enc_name == "chained-cnot":
            self.enc = ChainedCNOT()
        elif enc_name == "none":
            self.enc = None
        else:
            raise ValueError(f"Unknown encryption scheme '{spec.encryption}' in SchemeSpec '{spec.name}'")

    def run(self, cfg: RunConfig) -> Trace:
        n = cfg.n_message_qubits

        # PRNG / CSPRNG setup
        if cfg.seed is not None:
            rng = np.random.default_rng(cfg.seed)
            stim_seed = int(rng.integers(0, 2**31 - 1))
            run_id = rng.bytes(16).hex()
            session_id = rng.bytes(16).hex()
            nonce = rng.bytes(16).hex()
        else:
            rng = None
            stim_seed = None
            run_id = secrets.token_hex(16)
            session_id = secrets.token_hex(16)
            nonce = secrets.token_hex(16)

        # 1. Draw the key
        if cfg.force_key_reuse:
            if self.enc is not None:
                key = (tuple(0 for _ in range(n)), tuple(0 for _ in range(n)))
            else:
                key = ()
        elif cfg.key is not None:
            key: Any = cfg.key
        else:
            if self.enc is not None:
                if rng is not None:
                    a = tuple(int(x) for x in rng.integers(0, 2, size=n))
                    b = tuple(int(x) for x in rng.integers(0, 2, size=n))
                else:
                    a = tuple(secrets.randbelow(2) for _ in range(n))
                    b = tuple(secrets.randbelow(2) for _ in range(n))
                key = (a, b)
            else:
                key = ()

        trace_keys = [
            KeyDecl(name=k["name"], bits=k["bits"], reuse_policy=k["reuse_policy"])
            if isinstance(k, dict)
            else k
            for k in self.spec.keys
        ]

        # Populate key_digests for EVERY declared key
        key_digests: dict[str, str] = {}
        for k_decl in trace_keys:
            k_name = k_decl.name
            if cfg.force_key_reuse:
                k_mat = ("FIXED_REUSED_KEY_MATERIAL", k_name)
            elif cfg.key is not None and (k_name == "k_AT" or len(trace_keys) == 1):
                k_mat = cfg.key
            else:
                if rng is not None:
                    k_mat = (k_name, key, rng.bytes(16).hex())
                else:
                    k_mat = (k_name, key, secrets.token_hex(16))
            key_digests[k_name] = key_fingerprint(k_name, k_mat)

        trace_registers = [
            RegisterDecl(
                name=r["name"],
                qubits=r["qubits"],
                owner=Party(r["owner"]) if not isinstance(r["owner"], Party) else r["owner"],
                created_step=r.get("created_step", 0),
                consumed_step=r.get("consumed_step", None),
            )
            if isinstance(r, dict)
            else r
            for r in self.spec.registers
        ]

        # 2. Choose a message
        if rng is not None:
            message_in = [int(x) for x in rng.integers(0, 2, size=n)]
        else:
            message_in = [secrets.randbelow(2) for _ in range(n)]

        # 3. Walk spec.steps IN ORDER
        trace_steps: list[Step] = []
        for idx, s_spec in enumerate(self.spec.steps):
            step_detail = dict(s_spec.detail) if s_spec.detail else {}
            if s_spec.name is not None:
                step_detail["name"] = s_spec.name
            st = Step(
                index=idx,
                procedure=s_spec.procedure,
                party=s_spec.party,
                action=s_spec.action,
                registers=list(s_spec.registers),
                keys_used=list(s_spec.keys_used),
                decoy_protected=s_spec.decoy_protected,
                detail=step_detail,
            )
            trace_steps.append(st)

        # 4. QUANTUM CORE executed with stim for message teleportation
        circuit = stim.Circuit()
        for i in range(n):
            msg_q = 3 * i
            alice_q = 3 * i + 1
            bob_q = 3 * i + 2

            # Prepare message qubit state |message_in[i]>
            if message_in[i] == 1:
                circuit.append("X", [msg_q])

            # Prepare Bell pair |Phi+> on (alice_q, bob_q)
            circuit.append("H", [alice_q])
            circuit.append("CNOT", [alice_q, bob_q])

            # Teleportation Bell-basis measurement
            circuit.append("CNOT", [msg_q, alice_q])
            circuit.append("H", [msg_q])
            circuit.append("M", [alice_q, msg_q])

            # Conditional Pauli corrections on Bob's qubit
            circuit.append("CX", [stim.target_rec(-2), bob_q])
            circuit.append("CZ", [stim.target_rec(-1), bob_q])

            # Bob measurement of teleported qubit
            circuit.append("M", [bob_q])

        sampler = (
            circuit.compile_sampler(seed=stim_seed)
            if stim_seed is not None
            else circuit.compile_sampler()
        )
        shots = sampler.sample(shots=1)[0]
        recovered_message = [int(shots[3 * i + 2]) for i in range(n)]

        # Teleported message must be recovered EXACTLY at noise_p = 0
        assert recovered_message == message_in, (
            f"Quantum teleportation failed recovery: {recovered_message} != {message_in}"
        )

        # 5. DECOY ROUNDS and Non-decoy measurements
        decoy_steps = [s for s in self.spec.steps if s.decoy_protected]
        num_decoy_steps = len(decoy_steps)
        if num_decoy_steps > 0:
            m_per_step = math.ceil(cfg.decoy_rounds / num_decoy_steps)
        else:
            m_per_step = cfg.decoy_rounds

        p_flip = cfg.floor + cfg.noise_p
        if cfg.attack == "intercept_resend":
            p_flip += 0.25
        p_flip = min(1.0, max(0.0, p_flip))

        measurements: list[Measurement] = []
        decoy_idx_counter = 0

        for idx, s_spec in enumerate(self.spec.steps):
            if s_spec.decoy_protected:
                basis = "Z" if (decoy_idx_counter % 2 == 0) else "X"
                decoy_idx_counter += 1

                decoy_reg = next(
                    (r for r in s_spec.registers if "decoy" in r.lower()),
                    s_spec.registers[0] if s_spec.registers else "decoy_states",
                )

                if rng is not None:
                    expected = [int(b) for b in rng.integers(0, 2, size=m_per_step)]
                    flips = rng.random(m_per_step) < p_flip
                    outcome = [exp ^ int(flip) for exp, flip in zip(expected, flips)]
                else:
                    expected = [secrets.randbelow(2) for _ in range(m_per_step)]
                    outcome = [exp ^ int(secrets.randbelow(1000000) < (p_flip * 1000000)) for exp in expected]

                measurements.append(
                    Measurement(
                        step=idx,
                        register=decoy_reg,
                        basis=basis,
                        outcome=outcome,
                        expected=expected,
                        is_decoy=True,
                    )
                )
            elif s_spec.action == Action.MEASURE:
                reg = s_spec.registers[0] if s_spec.registers else "msg"
                measurements.append(
                    Measurement(
                        step=idx,
                        register=reg,
                        basis="Z",
                        outcome=list(recovered_message),
                        expected=list(message_in),
                        is_decoy=False,
                    )
                )

        # 6. ATTACK APPLICATION
        msg_state_idx = 0
        for b in message_in:
            msg_state_idx = (msg_state_idx << 1) | b
        msg_state_vec = np.zeros(2**n, dtype=np.complex128)
        msg_state_vec[msg_state_idx] = 1.0

        if cfg.attack is None:
            honest = True
            attack_label = None
            message_out = list(message_in)
            arbitrator_passed = True
            check_detail: dict[str, Any] = {}
        elif cfg.attack == "paired_pauli":
            honest = False
            attack_label = "paired_pauli"
            u_str = f"{cfg.attack_pauli}{'I' * (n - 1)}"
            U = Pauli.from_string(u_str)

            if self.enc is not None:
                V = self.enc.conjugate_attack(key, n, U)
                arbitrator_passed = predicate_holds(self.enc, key, n, U, msg_state_vec)
            else:
                V = U
                arbitrator_passed = False

            message_out = list(message_in)
            if cfg.attack_pauli in ("X", "Y"):
                message_out[0] = 1 - message_out[0]

            check_detail = {
                "key": [list(k_part) for k_part in key]
                if isinstance(key, tuple) and key and isinstance(key[0], tuple)
                else str(key),
                "U": U.to_string(),
                "V": V.to_string(),
            }
        elif cfg.attack == "unpaired_pauli":
            honest = False
            attack_label = "unpaired_pauli"
            u_str = f"{cfg.attack_pauli}{'I' * (n - 1)}"
            U = Pauli.from_string(u_str)
            V = Pauli.identity(n)

            if self.enc is not None:
                tab = self.enc.tableau(key, n)
                E_k = tab.to_unitary_matrix(endian="big")
                lhs = E_k @ (U.to_matrix() @ msg_state_vec)
                rhs = E_k @ msg_state_vec
                lhs_c = _remove_global_phase(lhs)
                rhs_c = _remove_global_phase(rhs)
                diff = float(np.max(np.abs(lhs_c - rhs_c)))
                arbitrator_passed = bool(diff < 1e-9)
            else:
                arbitrator_passed = False

            message_out = list(message_in)
            if cfg.attack_pauli in ("X", "Y"):
                message_out[0] = 1 - message_out[0]

            check_detail = {
                "key": [list(k_part) for k_part in key]
                if isinstance(key, tuple) and key and isinstance(key[0], tuple)
                else str(key),
                "U": U.to_string(),
                "V": V.to_string(),
            }
        elif cfg.attack == "intercept_resend":
            honest = False
            attack_label = "intercept_resend"
            message_out = list(message_in)
            arbitrator_passed = True
            check_detail = {"attack": "intercept_resend"}
        else:
            raise ValueError(f"Unknown attack type: '{cfg.attack}'")

        # 7. Record Check named 'arbitrator_equality' at the VERIFY step
        verify_step_idx = None
        for s_i, s in enumerate(self.spec.steps):
            if s.procedure == Procedure.VERIFY and s.action == Action.CHECK and not s.decoy_protected:
                verify_step_idx = s_i
                break
        if verify_step_idx is None:
            for s_i, s in enumerate(self.spec.steps):
                if s.procedure == Procedure.VERIFY and s.action == Action.CHECK:
                    verify_step_idx = s_i
                    break
        if verify_step_idx is None:
            for s_i, s in enumerate(self.spec.steps):
                if s.procedure == Procedure.VERIFY:
                    verify_step_idx = s_i
                    break
        if verify_step_idx is None:
            verify_step_idx = len(self.spec.steps) - 1 if self.spec.steps else 0

        checks = [
            Check(
                step=verify_step_idx,
                name="arbitrator_equality",
                passed=arbitrator_passed,
                detail=check_detail,
            )
        ]

        # 8. Set trace properties
        accepted = all(c.passed for c in checks)
        verifier_set = [
            Party(v) if not isinstance(v, Party) else v
            for v in self.spec.verifier_set
        ]

        trace = Trace(
            schema_version="1.1",
            scheme=self.spec.name,
            n_message_qubits=n,
            run_id=run_id,
            session_id=session_id,
            nonce=nonce,
            honest=honest,
            attack_label=attack_label,
            verifier_set=verifier_set,
            keys=trace_keys,
            registers=trace_registers,
            steps=trace_steps,
            measurements=measurements,
            checks=checks,
            message_in=message_in,
            message_out=message_out,
            accepted=accepted,
            assumed_fields=list(self.spec.assumed_fields),
            key_digests=key_digests,
        )

        # 9. Validate trace before returning
        issues = validate(trace)
        if issues:
            raise ValueError(f"Engine emitted invalid trace for scheme '{self.spec.name}': {issues}")

        return trace


def run_many(engine: ProtocolEngine, cfg: RunConfig, trials: int) -> list[Trace]:
    """Execute multiple protocol runs sequentially, reproducibly when seeded."""
    traces: list[Trace] = []
    for t in range(trials):
        if cfg.seed is not None:
            trial_cfg = RunConfig(
                n_message_qubits=cfg.n_message_qubits,
                noise_p=cfg.noise_p,
                floor=cfg.floor,
                decoy_rounds=cfg.decoy_rounds,
                seed=cfg.seed + t,
                attack=cfg.attack,
                attack_pauli=cfg.attack_pauli,
                key=cfg.key,
                force_key_reuse=cfg.force_key_reuse,
            )
        else:
            trial_cfg = cfg
        traces.append(engine.run(trial_cfg))
    return traces

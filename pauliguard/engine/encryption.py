"""Quantum encryption models for Arbitrated Quantum Signature (AQS) schemes.

Models key-controlled encryption E_k and evaluates how E_k conjugates
a Pauli attack operator U (i.e. V = E_k U E_k^dagger).

PROVEN:
- Under QOTP (E_k = prod_i X^{a_i} Z^{b_i}), for every key k in {0,1}^{2n}
  and every Pauli operator U, E_k U E_k^dagger = (-1)^c U for some c in {0, 1}.
  That is, Pauli letters (the x and z bit vectors) are INVARIANT under QOTP conjugation.
- Under non-trivial Clifford circuits (e.g. ChainedCNOT), conjugation spreads
  Pauli letters across qubits, so pauli_letters_preserved is FALSE.
"""

from __future__ import annotations

import abc
import itertools
import math
import random
from typing import Iterator, Tuple

import stim

from pauliguard.engine.pauli import Pauli, conjugate

Key = Tuple[Tuple[int, ...], ...]



class Encryption(abc.ABC):
    """Abstract base class modeling key-controlled encryption E_k."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Return the canonical name of the encryption scheme."""
        raise NotImplementedError

    @abc.abstractmethod
    def keyspace_size(self, n: int) -> int:
        """Return the size of the keyspace for n qubits."""
        raise NotImplementedError

    @abc.abstractmethod
    def iter_keys(self, n: int) -> Iterator[Key]:
        """Enumerate the full keyspace for n qubits."""
        raise NotImplementedError

    @abc.abstractmethod
    def tableau(self, key: Key, n: int) -> stim.Tableau:
        """Return the stim.Tableau Clifford implementing E_k."""
        raise NotImplementedError

    def conjugate_attack(self, key: Key, n: int, U: Pauli) -> Pauli:
        """Conjugate a Pauli attack operator U under E_k, returning V = E_k U E_k^dagger."""
        if U.n != n:
            raise ValueError(f"Pauli operator qubit count {U.n} does not match n={n}")
        tab = self.tableau(key, n)
        return conjugate(tab, U)


class QOTP(Encryption):
    """Quantum One-Time Pad encryption E_k = prod_{i=0}^{n-1} X^{a_i} Z^{b_i}."""

    @property
    def name(self) -> str:
        return "qotp"

    def keyspace_size(self, n: int) -> int:
        """Keyspace size is 4**n = 2**n * 2**n for bit keys (a, b)."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        return 4**n

    def iter_keys(self, n: int) -> Iterator[Key]:
        """Enumerate all 4**n keys (a, b) where a, b in {0, 1}^n."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        bit_tuples = list(itertools.product((0, 1), repeat=n))
        for a in bit_tuples:
            for b in bit_tuples:
                yield (a, b)

    def tableau(self, key: Key, n: int) -> stim.Tableau:
        """Build the Clifford tableau from a stim.Circuit applying X where a_i=1 and Z where b_i=1."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        a, b = key
        if len(a) != n or len(b) != n:
            raise ValueError(
                f"Key bit tuples must have length n={n}, got len(a)={len(a)}, len(b)={len(b)}"
            )

        circuit = stim.Circuit()
        if n > 0:
            circuit.append("I", list(range(n)))
        for i in range(n):
            if a[i]:
                circuit.append("X", [i])
            if b[i]:
                circuit.append("Z", [i])
        return stim.Tableau.from_circuit(circuit)


class ChainedCNOT(Encryption):
    """Encryption with X/Z layer followed by a fixed CNOT chain CNOT(0->1), ..., CNOT(n-2->n-1)."""

    @property
    def name(self) -> str:
        return "chained-cnot"

    def keyspace_size(self, n: int) -> int:
        """Keyspace size is 4**n for bit keys (a, b)."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        return 4**n

    def iter_keys(self, n: int) -> Iterator[Key]:
        """Enumerate all 4**n keys (a, b) where a, b in {0, 1}^n."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        bit_tuples = list(itertools.product((0, 1), repeat=n))
        for a in bit_tuples:
            for b in bit_tuples:
                yield (a, b)

    def tableau(self, key: Key, n: int) -> stim.Tableau:
        """Build tableau with X/Z layer followed by CNOT(0->1), ..., CNOT(n-2->n-1)."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        a, b = key
        if len(a) != n or len(b) != n:
            raise ValueError(
                f"Key bit tuples must have length n={n}, got len(a)={len(a)}, len(b)={len(b)}"
            )

        circuit = stim.Circuit()
        if n > 0:
            circuit.append("I", list(range(n)))
        for i in range(n):
            if a[i]:
                circuit.append("X", [i])
            if b[i]:
                circuit.append("Z", [i])
        for i in range(n - 1):
            circuit.append("CNOT", [i, i + 1])
        return stim.Tableau.from_circuit(circuit)


class PermutedChainedCNOT(Encryption):
    """Encryption with X/Z layer, CNOT chain, and a key-controlled qubit permutation.

    HONESTY CAVEAT: This is OUR construction implementing the mechanism as described
    secondhand, not the exact published construction from Jacqmin-Lienardy (we do not have
    the source paper). Any scaling or agreement with published figures (e.g. 1/(8n)) is a
    CONSISTENCY OBSERVATION, never a reproduction claim.

    Key is a triple (a, b, tau) where a and b are length-n bit tuples and tau is a
    PERMUTATION of range(n) represented as a tuple.
    E_k is applied in this order:
      1. X^a_i Z^b_i on each qubit i
      2. the CNOT chain CNOT(0->1), CNOT(1->2), ..., CNOT(n-2 -> n-1)
      3. the qubit permutation tau, implemented as a network of SWAP gates
    """

    @property
    def name(self) -> str:
        return "permuted-chained-cnot"

    def keyspace_size(self, n: int) -> int:
        """Return keyspace size: 4**n * factorial(n)."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        return (4**n) * math.factorial(n)

    def iter_keys(self, n: int) -> Iterator[Key]:
        """Enumerate the full keyspace (a, b, tau) for n qubits."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        bit_tuples = list(itertools.product((0, 1), repeat=n))
        perms = list(itertools.permutations(range(n)))
        for a in bit_tuples:
            for b in bit_tuples:
                for tau in perms:
                    yield (a, b, tau)

    def sample_keys(
        self,
        n: int,
        count: int,
        rng: random.Random | int | None = None,
    ) -> Iterator[Key]:
        """Yield `count` uniformly sampled random keys (a, b, tau) for n qubits."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        if count < 0:
            raise ValueError(f"Count must be non-negative, got {count}")
        if rng is None:
            r = random.Random()
        elif isinstance(rng, int):
            r = random.Random(rng)
        else:
            r = rng

        for _ in range(count):
            a = tuple(r.randint(0, 1) for _ in range(n))
            b = tuple(r.randint(0, 1) for _ in range(n))
            tau_list = list(range(n))
            r.shuffle(tau_list)
            yield (a, b, tuple(tau_list))

    def tableau(self, key: Key, n: int) -> stim.Tableau:
        """Build stim.Tableau for the whole composition: X/Z -> CNOT chain -> permutation."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        if len(key) != 3:
            raise ValueError(f"Key must be a triple (a, b, tau), got length {len(key)}")
        a, b, tau = key
        if len(a) != n or len(b) != n or len(tau) != n:
            raise ValueError(
                f"Key components must have length n={n}, got len(a)={len(a)}, len(b)={len(b)}, len(tau)={len(tau)}"
            )
        if sorted(tau) != list(range(n)):
            raise ValueError(f"tau must be a permutation of range({n}), got {tau}")

        lines: list[str] = []

        # 1. X^a_i Z^b_i on each qubit i
        for i in range(n):
            if a[i]:
                lines.append(f"X {i}")
            if b[i]:
                lines.append(f"Z {i}")

        # 2. CNOT chain CNOT(0->1), CNOT(1->2), ..., CNOT(n-2 -> n-1)
        for i in range(n - 1):
            lines.append(f"CNOT {i} {i + 1}")

        # 3. Qubit permutation tau via SWAP gate network
        pos = list(range(n))
        inv = list(range(n))
        for i in range(n):
            curr = pos[i]
            dest = tau[i]
            if curr != dest:
                k = inv[dest]
                lines.append(f"SWAP {curr} {dest}")
                pos[i], pos[k] = dest, curr
                inv[dest], inv[curr] = i, k

        if not lines:
            return stim.Tableau(n)
        if n > 0:
            lines.insert(0, f"I {n - 1}")
        return stim.Tableau.from_circuit(stim.Circuit("\n".join(lines)))


def pauli_letters_preserved(enc: Encryption, n: int, U: Pauli) -> bool:
    """Return True iff for EVERY key in enc.iter_keys(n), conjugate_attack(key, n, U)

    has the same x and z bit vectors as U (i.e. differs from U by at most a SIGN/phase,
    never in which Pauli letters appear).
    """
    if U.n != n:
        raise ValueError(f"Pauli operator qubit count {U.n} does not match n={n}")
    for key in enc.iter_keys(n):
        v = enc.conjugate_attack(key, n, U)
        if v.x != U.x or v.z != U.z:
            return False
    return True


class KCCC(Encryption):
    """Key-Controlled Chained-CNOT (KCCC) encryption from Jacqmin-Liénardy arXiv:2603.19985.

    The exact construction consists of three sequential Clifford layers:
      E^KCCC_{k1||k2||k3} = E^perm_k3 o H_k2 o E^CNOT_k1

    Layer 1 (E^CNOT_k1):
      k1 is a permutation of (1, ..., n), where k1(i) is the image of i.
      E^CNOT_k1 = CNOT_{n, k1(n)} ... CNOT_{2, k1(2)} CNOT_{1, k1(1)}
      applied in increasing i order (i=1 first). CNOT_{i, j} maps |P_i>|P_j> -> |P_i>|P_i XOR P_j>
      (control i, target j). CRITICALLY: CNOT_{i, i} is the IDENTITY operator.
      So if k1(1) = 1, the first CNOT does nothing.

    Layer 2 (H_k2):
      k2 in {0, 1}^n. Apply the Hadamard gate H to qubit i if and only if k2_i = 1.

    Layer 3 (E^perm_k3):
      k3 in {0, 1}^n. Two variants:
        (a) "transp": for each i in {1, ..., floor(n/2)} define tau_i = k3_i XOR k3_{n+1-i}.
            S^{tau_i}_{i, n+1-i} is identity if tau_i = 0 and SWAPS qubits i and n+1-i if tau_i = 1.
            E^transp_k3 = S^{tau_floor(n/2)}_{floor(n/2), ceil(n/2)+1} o ... o S^{tau_1}_{1, n}
        (b) "rot": tau = (sum_i k3_i) mod n, and S^{(tau)}_n rotates:
            |P_1, ..., P_n> -> |P_{tau+1}, ..., P_n, P_1, ..., P_tau>

    Key is a triple (k1, k2, k3):
      - k1: a permutation tuple of range(n) (0-based image list)
      - k2: bit tuple of length n
      - k3: bit tuple of length n
    """

    def __init__(self, perm_variant: str = "transp") -> None:
        if perm_variant not in ("transp", "rot"):
            raise ValueError(
                f"Unknown perm_variant '{perm_variant}'. Must be 'transp' or 'rot'."
            )
        self.perm_variant = perm_variant

    @property
    def name(self) -> str:
        return "kccc"

    def keyspace_size(self, n: int) -> int:
        """Keyspace size is factorial(n) * 2**n * 2**n = factorial(n) * 4**n."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        return math.factorial(n) * (4**n)

    def iter_keys(self, n: int) -> Iterator[Key]:
        """Enumerate the full keyspace (k1, k2, k3) for n qubits."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        perms = list(itertools.permutations(range(n)))
        bit_tuples = list(itertools.product((0, 1), repeat=n))
        for k1 in perms:
            for k2 in bit_tuples:
                for k3 in bit_tuples:
                    yield (k1, k2, k3)

    def sample_keys(
        self,
        n: int,
        count: int,
        rng: random.Random | int | None = None,
    ) -> Iterator[Key]:
        """Yield `count` uniformly sampled random keys (k1, k2, k3) for n qubits."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        if count < 0:
            raise ValueError(f"Count must be non-negative, got {count}")
        if rng is None:
            r = random.Random()
        elif isinstance(rng, int):
            r = random.Random(rng)
        else:
            r = rng

        for _ in range(count):
            k1_list = list(range(n))
            r.shuffle(k1_list)
            k2 = tuple(r.randint(0, 1) for _ in range(n))
            k3 = tuple(r.randint(0, 1) for _ in range(n))
            yield (tuple(k1_list), k2, k3)

    def tableau(self, key: Key, n: int) -> stim.Tableau:
        """Build stim.Tableau for E^perm_k3 o H_k2 o E^CNOT_k1 in that order."""
        if n < 0:
            raise ValueError(f"Qubit count n must be non-negative, got {n}")
        if len(key) != 3:
            raise ValueError(f"Key must be a triple (k1, k2, k3), got length {len(key)}")
        k1, k2, k3 = key
        if len(k1) != n or len(k2) != n or len(k3) != n:
            raise ValueError(
                f"Key components must have length n={n}, got len(k1)={len(k1)}, len(k2)={len(k2)}, len(k3)={len(k3)}"
            )
        if len(set(k1)) != n or any(x < 0 or x >= n for x in k1):
            raise ValueError(f"k1 must be a permutation of range({n}), got {k1}")

        lines: list[str] = []

        # LAYER 1: E^CNOT_k1
        # CNOT_{n, k1(n)} ... CNOT_{2, k1(2)} CNOT_{1, k1(1)}
        # Applied in increasing i order (i=0 first in 0-based indexing).
        # CNOT_{i, i} is the identity operator.
        for i in range(n):
            target = k1[i]
            if i != target:
                lines.append(f"CNOT {i} {target}")

        # LAYER 2: H_k2
        # Apply Hadamard to qubit i iff k2[i] == 1
        for i in range(n):
            if k2[i]:
                lines.append(f"H {i}")

        # LAYER 3: E^perm_k3
        if self.perm_variant == "transp":
            for i in range(n // 2):
                tau_i = k3[i] ^ k3[n - 1 - i]
                if tau_i:
                    lines.append(f"SWAP {i} {n - 1 - i}")
        elif self.perm_variant == "rot":
            tau = sum(k3) % n if n > 0 else 0
            if tau != 0:
                # |P_0, ..., P_{n-1}> -> |P_tau, ..., P_{n-1}, P_0, ..., P_{tau-1}>
                # Original qubit i moves to wire (i - tau) % n
                perm = [(i - tau) % n for i in range(n)]
                pos = list(range(n))
                inv = list(range(n))
                for i in range(n):
                    curr = pos[i]
                    dest = perm[i]
                    if curr != dest:
                        other = inv[dest]
                        lines.append(f"SWAP {curr} {dest}")
                        pos[i], pos[other] = dest, curr
                        inv[dest], inv[curr] = i, other

        if not lines:
            return stim.Tableau(n)
        if n > 0:
            lines.insert(0, f"I {n - 1}")
        return stim.Tableau.from_circuit(stim.Circuit("\n".join(lines)))


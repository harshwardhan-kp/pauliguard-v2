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
from typing import Iterator, Tuple

import stim

from pauliguard.engine.pauli import Pauli, conjugate

Key = Tuple[Tuple[int, ...], Tuple[int, ...]]


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

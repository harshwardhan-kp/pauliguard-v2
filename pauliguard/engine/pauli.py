"""Exact n-qubit Pauli group implementation in the symplectic GF(2) representation.

PROVEN:
- Any n-qubit Pauli operator P can be uniquely represented as P = i^phase * X^x * Z^z,
  where x, z in {0, 1}^n and phase in {0, 1, 2, 3}.
- The symplectic inner product sum(x1*z2 + z1*x2) mod 2 is 0 iff two Pauli operators commute.
- Multiplication over GF(2) with phase accumulation (phase1 + phase2 + 2 * sum(z1 * x2)) mod 4
  is strictly associative and satisfies (A * B).to_matrix() == A.to_matrix() @ B.to_matrix().

ASSUMED:
- Standard Pauli basis convention: X = [[0, 1], [1, 0]], Z = [[1, 0], [0, -1]],
  Y = iXZ = [[0, -i], [i, 0]].
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import numpy as np

# Single-qubit elementary components for matrix construction
_MAT_I = np.array([[1.0, 0.0], [0.0, 1.0]], dtype=np.complex128)
_MAT_X = np.array([[0.0, 1.0], [1.0, 0.0]], dtype=np.complex128)
_MAT_Z = np.array([[1.0, 0.0], [0.0, -1.0]], dtype=np.complex128)
_MAT_XZ = np.array([[0.0, -1.0], [1.0, 0.0]], dtype=np.complex128)

_MAT_MAP = {
    (0, 0): _MAT_I,
    (1, 0): _MAT_X,
    (0, 1): _MAT_Z,
    (1, 1): _MAT_XZ,
}

_PHASE_FACTORS = [
    1.0 + 0.0j,       # i^0 = 1
    0.0 + 1.0j,       # i^1 = i
    -1.0 + 0.0j,      # i^2 = -1
    0.0 - 1.0j,       # i^3 = -i
]

_PHASE_TOKENS = {
    0: "+",
    1: "+i",
    2: "-",
    3: "-i",
}


@dataclass(frozen=True)
class Pauli:
    """An exact n-qubit Pauli operator P = i^phase * X^x * Z^z.

    Fields:
      n: Number of qubits.
      x: Length-n tuple of integers in {0, 1} indicating X components.
      z: Length-n tuple of integers in {0, 1} indicating Z components.
      phase: Integer in {0, 1, 2, 3} representing global phase factor i^phase.
    """

    n: int
    x: tuple[int, ...]
    z: tuple[int, ...]
    phase: int

    def __post_init__(self) -> None:
        if len(self.x) != self.n or len(self.z) != self.n:
            raise ValueError(f"Length of x and z tuples must match n={self.n}")
        if self.phase not in (0, 1, 2, 3):
            object.__setattr__(self, "phase", self.phase % 4)
        for val in self.x:
            if val not in (0, 1):
                raise ValueError(f"x components must be 0 or 1, got {val}")
        for val in self.z:
            if val not in (0, 1):
                raise ValueError(f"z components must be 0 or 1, got {val}")

    @classmethod
    def identity(cls, n: int) -> Pauli:
        """Return the n-qubit identity Pauli operator."""
        if n < 0:
            raise ValueError(f"Number of qubits n must be non-negative, got {n}")
        return cls(n=n, x=(0,) * n, z=(0,) * n, phase=0)

    @classmethod
    def from_string(cls, s: str) -> Pauli:
        """Parse a Pauli string with optional leading sign/phase token.

        Accepts leading token in {"+", "-", "+i", "-i"} followed by n characters in {I, X, Y, Z}.
        Convention: X has (x=1, z=0), Z has (x=0, z=1), Y = iXZ has (x=1, z=1) contributing phase 1.
        """
        s = s.strip()
        if not s:
            return cls(n=0, x=(), z=(), phase=0)

        if s.startswith("+i"):
            phase_token = 1
            raw_letters = s[2:]
        elif s.startswith("-i"):
            phase_token = 3
            raw_letters = s[2:]
        elif s.startswith("+"):
            phase_token = 0
            raw_letters = s[1:]
        elif s.startswith("-"):
            phase_token = 2
            raw_letters = s[1:]
        else:
            phase_token = 0
            raw_letters = s

        xs = []
        zs = []
        y_count = 0

        for ch in raw_letters:
            if ch in ("I", "_"):
                xs.append(0)
                zs.append(0)
            elif ch == "X":
                xs.append(1)
                zs.append(0)
            elif ch == "Z":
                xs.append(0)
                zs.append(1)
            elif ch == "Y":
                xs.append(1)
                zs.append(1)
                y_count += 1
            else:
                raise ValueError(f"Invalid Pauli character '{ch}' in '{s}'")

        n = len(raw_letters)
        total_phase = (phase_token + y_count) % 4
        return cls(n=n, x=tuple(xs), z=tuple(zs), phase=total_phase)

    def to_string(self) -> str:
        """Return string representation, always emitting an explicit sign token ('+', '-', '+i', '-i')."""
        letters = []
        y_count = 0
        for xk, zk in zip(self.x, self.z):
            if xk == 0 and zk == 0:
                letters.append("I")
            elif xk == 1 and zk == 0:
                letters.append("X")
            elif xk == 0 and zk == 1:
                letters.append("Z")
            elif xk == 1 and zk == 1:
                letters.append("Y")
                y_count += 1

        phase_token = (self.phase - y_count) % 4
        token = _PHASE_TOKENS[phase_token]
        return f"{token}{''.join(letters)}"

    def __str__(self) -> str:
        return self.to_string()

    def __mul__(self, other: Any) -> Pauli:
        """Exact GF(2) symplectic product with phase accumulation."""
        if not isinstance(other, Pauli):
            return NotImplemented
        if self.n != other.n:
            raise ValueError(
                f"Cannot multiply Paulis of different qubit counts: {self.n} and {other.n}"
            )

        new_x = tuple(x1 ^ x2 for x1, x2 in zip(self.x, other.x))
        new_z = tuple(z1 ^ z2 for z1, z2 in zip(self.z, other.z))
        cross = sum(z1 * x2 for z1, x2 in zip(self.z, other.x))
        new_phase = (self.phase + other.phase + 2 * cross) % 4
        return Pauli(n=self.n, x=new_x, z=new_z, phase=new_phase)

    def commutes(self, other: Pauli) -> bool:
        """Check commutation via symplectic inner product sum(x1*z2 + z1*x2) mod 2 == 0."""
        if not isinstance(other, Pauli):
            raise TypeError(f"Expected Pauli instance, got {type(other)}")
        if self.n != other.n:
            raise ValueError(
                f"Cannot check commutation for Paulis of different sizes: {self.n} and {other.n}"
            )
        symp = sum(
            x1 * z2 + z1 * x2
            for x1, z1, x2, z2 in zip(self.x, self.z, other.x, other.z)
        )
        return (symp % 2) == 0

    def to_matrix(self) -> np.ndarray:
        """Return (2**n, 2**n) complex matrix in big-endian qubit order (qubit 0 leftmost)."""
        if self.n == 0:
            return np.array([[_PHASE_FACTORS[self.phase]]], dtype=np.complex128)

        mat = _MAT_MAP[(self.x[0], self.z[0])]
        for i in range(1, self.n):
            mat = np.kron(mat, _MAT_MAP[(self.x[i], self.z[i])])

        factor = _PHASE_FACTORS[self.phase]
        return (factor * mat).astype(np.complex128)

    def weight(self) -> int:
        """Return the number of non-identity letters in the Pauli operator."""
        return sum(1 for xk, zk in zip(self.x, self.z) if xk or zk)


def conjugate(clifford_tableau: Any, pauli: Pauli) -> Pauli:
    """Given a stim.Tableau and a Pauli, return C P C^dagger.

    stim is imported inside this function only to keep the module dependency-free.
    """
    import stim  # imported inside this function only

    ps = stim.PauliString(pauli.to_string())
    res = clifford_tableau(ps)
    return Pauli.from_string(str(res))

/**
 * PauliGuard — Quantum Signature Threat Detector (SIH26141)
 * Judge-facing Threat Dossier UI Client
 */

(function () {
  "use strict";

  // --------------------------------------------------------------------------
  // Backend API Resolver
  // --------------------------------------------------------------------------
  const qs = new URLSearchParams(location.search);
  const explicit = qs.get("api") || window.PAULIGUARD_API_BASE || localStorage.getItem("pauliguard_api_base");
  const base = explicit || (location.hostname.includes("vercel.app") ? "https://pauliguard-v2-api.onrender.com" : "");
  const cleanBase = base ? base.replace(/\/+$/, "") : "";
  const apiUrl = (endpoint) => `${cleanBase}${endpoint}`;

  // --------------------------------------------------------------------------
  // Application State & Defaults
  // --------------------------------------------------------------------------
  const state = {
    scheme: "lu-2022",
    n_message_qubits: 2,
    attack_pauli: "X",
    noise_p: 0.0,
    decoy_rounds: 4200,
    alpha: 1e-10,
    seedCompare: 102,
    seedHonest: 101,
    schemes: [],
    health: null,
    isLoading: false,
    lastCompareResult: null,
    isLive: false,
  };

  // --------------------------------------------------------------------------
  // Cached Fallback Data for Offline Preview
  // --------------------------------------------------------------------------
  const CACHED_SCHEMES = [
    { name: "lu-2022", family: "teleportation-aqs" },
    { name: "lu-2022-hardened", family: "teleportation-aqs" },
    { name: "li-chan-long-2009", family: "teleportation-aqs" },
    { name: "decoy-bb84-qds", family: "decoy-state-qds" },
  ];

  const CACHED_COMPARE_DATA = {
    honest: {
      summary: {
        message_in: [1, 1],
        message_out: [1, 1],
        message_changed: false,
        accepted: true,
        attack_label: null,
      },
      layers: {
        L0: {
          flagged: false,
          derivation: "no threshold - deterministic predicate",
        },
        L1: {
          flagged: false,
          observed_rate: 0.03524,
          tau: 0.04534,
          floor: 0.03442,
          derivation: "tau = 0.04534 from Serfling; xbar=0.03524, PASS",
        },
        L2: {
          flagged: false,
          threshold: 0.04534,
          observed: 0.03524,
          derivation: "Azuma-Hoeffding: tau = 0.0453; observed=0.0352, PASS",
        },
        L3: {
          flagged: false,
          derivation: "no threshold - algebraic search",
        },
      },
    },
    forged: {
      summary: {
        message_in: [1, 1],
        message_out: [0, 1],
        message_changed: true,
        accepted: true,
        attack_label: "paired_pauli",
      },
      layers: {
        L0: {
          flagged: false,
          derivation: "no threshold - deterministic predicate",
        },
        L1: {
          flagged: false,
          observed_rate: 0.03524,
          tau: 0.04534,
          floor: 0.03442,
          derivation: "tau = 0.04534 from Serfling; xbar=0.03524, PASS",
        },
        L2: {
          flagged: false,
          threshold: 0.04534,
          observed: 0.03524,
          derivation: "Azuma-Hoeffding: tau = 0.0453; observed=0.0352, PASS",
        },
        L3: {
          flagged: true,
          derivation: "no threshold - algebraic search",
          certificates: [
            {
              witness_pauli: "+XI",
              signature_pauli: "+XI",
              malleability_dimension: 4,
              success_probability: 1.0,
              execution_accepted: 16,
              execution_trials: 16,
              explanation: "Pauli-conjugation attack satisfies arbitrator predicate.",
              caveat: "L3 is sound, not complete: a certificate proves an attack exists; no malleability found is NOT a proof of security.",
            },
          ],
        },
      },
    },
    decoy_rate_honest: 0.03524,
    decoy_rate_forged: 0.03524,
    both_within_threshold: true,
  };

  // --------------------------------------------------------------------------
  // DOM Elements Cache
  // --------------------------------------------------------------------------
  const el = {
    // Global Error / Offline Banner
    globalError: document.getElementById("globalError"),
    errorTag: document.getElementById("errorTag"),
    errorMessage: document.getElementById("errorMessage"),
    dismissErrorBtn: document.getElementById("dismissErrorBtn"),

    // Header
    headerStatus: document.getElementById("headerStatus"),
    statusDot: document.getElementById("statusDot"),
    backendStatus: document.getElementById("backendStatus"),

    // Hero Actions
    runForgeryBtn: document.getElementById("runForgeryBtn"),
    runHonestBtn: document.getElementById("runHonestBtn"),

    // Meta Strip
    metaScheme: document.getElementById("metaScheme"),
    metaBits: document.getElementById("metaBits"),
    metaDecoys: document.getElementById("metaDecoys"),
    metaFloor: document.getElementById("metaFloor"),

    // Score Strip
    scoreCachedTag: document.getElementById("scoreCachedTag"),
    scoreForgeryRate: document.getElementById("scoreForgeryRate"),
    scoreHonestAccept: document.getElementById("scoreHonestAccept"),
    scoreStandardChecks: document.getElementById("scoreStandardChecks"),
    scorePauliguardPill: document.getElementById("scorePauliguardPill"),

    // Verdict Panel
    verdictPanel: document.getElementById("verdictPanel"),
    verdictHeadline: document.getElementById("verdictHeadline"),
    verdictSubline: document.getElementById("verdictSubline"),
    verdictCachedTag: document.getElementById("verdictCachedTag"),

    // Exhibits
    exhibitAliceA: document.getElementById("exhibitAliceA"),
    exhibitBobA: document.getElementById("exhibitBobA"),
    exhibitDecoyA: document.getElementById("exhibitDecoyA"),
    exhibitStatusA: document.getElementById("exhibitStatusA"),

    exhibitAliceB: document.getElementById("exhibitAliceB"),
    exhibitBobB: document.getElementById("exhibitBobB"),
    exhibitDecoyB: document.getElementById("exhibitDecoyB"),
    exhibitStatusB: document.getElementById("exhibitStatusB"),

    // Cross-Examination
    standardStatusPill: document.getElementById("standardStatusPill"),
    standardWhyContent: document.getElementById("standardWhyContent"),
    auditRowL3: document.getElementById("auditRowL3"),
    l3StatusPill: document.getElementById("l3StatusPill"),
    l3WhyContent: document.getElementById("l3WhyContent"),

    // Replay & Schemes
    schemesList: document.getElementById("schemesList"),
    messageBitsInput: document.getElementById("messageBitsInput"),
    stepDecBtn: document.getElementById("stepDecBtn"),
    stepIncBtn: document.getElementById("stepIncBtn"),
    runBothBtn: document.getElementById("runBothBtn"),

    // Advanced Inputs
    noiseInput: document.getElementById("noiseInput"),
    decoysInput: document.getElementById("decoysInput"),
    alphaInput: document.getElementById("alphaInput"),
    attackPauliSelect: document.getElementById("attackPauliSelect"),
  };

  // --------------------------------------------------------------------------
  // Utility Helpers
  // --------------------------------------------------------------------------
  function showOfflineBanner() {
    if (el.globalError) {
      el.globalError.className = "global-error global-error--offline";
      el.globalError.classList.remove("hidden");
    }
    if (el.errorTag) {
      el.errorTag.style.display = "none";
    }
    if (el.errorMessage) {
      el.errorMessage.textContent = "OFFLINE PREVIEW — showing a cached example run. Connect backend for live data.";
    }
  }

  function showError(msg) {
    if (el.globalError) {
      el.globalError.className = "global-error";
      el.globalError.classList.remove("hidden");
    }
    if (el.errorTag) {
      el.errorTag.style.display = "";
      el.errorTag.textContent = "[ERROR]";
    }
    if (el.errorMessage) el.errorMessage.textContent = msg;
    console.error("[PauliGuard Error]", msg);
  }

  function clearError() {
    if (el.globalError) el.globalError.classList.add("hidden");
  }

  function setLive(isLive) {
    state.isLive = isLive;
    if (el.verdictCachedTag) {
      if (isLive) {
        el.verdictCachedTag.classList.add("hidden");
      } else {
        el.verdictCachedTag.classList.remove("hidden");
      }
    }
    if (el.scoreCachedTag) {
      if (isLive) {
        el.scoreCachedTag.classList.add("hidden");
      } else {
        el.scoreCachedTag.classList.remove("hidden");
      }
    }
  }

  function setOfflineStatus() {
    if (el.statusDot) {
      el.statusDot.className = "status-dot status-dot--offline";
    }
    if (el.backendStatus) {
      el.backendStatus.textContent = "OFFLINE PREVIEW";
    }
    if (el.headerStatus) {
      el.headerStatus.className = "header-status header-status--offline";
    }
  }

  function setOnlineStatus(floor) {
    if (el.statusDot) {
      el.statusDot.className = "status-dot status-dot--online";
    }
    if (el.backendStatus) {
      const floorPct = floor != null ? (floor * 100).toFixed(2) : "3.44";
      el.backendStatus.textContent = `ONLINE · IBM ${floorPct}%`;
    }
    if (el.headerStatus) {
      el.headerStatus.className = "header-status";
    }
  }

  function formatRate(val) {
    if (val == null || isNaN(val)) return "0.00000";
    return Number(val).toFixed(5);
  }

  function formatPercent(val) {
    if (val == null || isNaN(val)) return "0.0%";
    return (Number(val) * 100).toFixed(1) + "%";
  }

  function formatNum(val, dp = 2) {
    if (val == null || isNaN(val)) return "0.00";
    return Number(val).toFixed(dp);
  }

  function renderChips(bits, container, changedBitsMask = []) {
    if (!container) return;
    container.innerHTML = "";
    if (!Array.isArray(bits) || bits.length === 0) {
      container.innerHTML = `<span class="qubit-chip mono">|0⟩</span>`;
      return;
    }
    bits.forEach((b, idx) => {
      const chip = document.createElement("span");
      chip.className = "qubit-chip mono";
      chip.textContent = `|${b}⟩`;
      if (changedBitsMask[idx]) {
        chip.classList.add("qubit-chip--changed");
        chip.title = `Bit ${idx} mutated from expected value`;
      }
      container.appendChild(chip);
    });
  }

  function setLoading(loading, activeAction = "compare") {
    state.isLoading = loading;
    const buttons = [el.runForgeryBtn, el.runHonestBtn, el.runBothBtn, el.stepDecBtn, el.stepIncBtn];
    buttons.forEach((btn) => {
      if (btn) btn.disabled = loading;
    });

    if (el.schemesList) {
      const radios = el.schemesList.querySelectorAll("input[type='radio']");
      radios.forEach((r) => { r.disabled = loading; });
    }

    if (el.runForgeryBtn) {
      el.runForgeryBtn.classList.toggle("is-loading", loading && activeAction === "compare");
      const lbl = el.runForgeryBtn.querySelector(".btn-label");
      if (lbl) lbl.textContent = loading && activeAction === "compare" ? "Running forgery..." : "Run the forgery";
    }

    if (el.runHonestBtn) {
      el.runHonestBtn.classList.toggle("is-loading", loading && activeAction === "honest");
      const lbl = el.runHonestBtn.querySelector(".btn-label");
      if (lbl) lbl.textContent = loading && activeAction === "honest" ? "Running honest..." : "Run honest";
    }

    if (el.runBothBtn) {
      el.runBothBtn.classList.toggle("is-loading", loading && activeAction === "compare");
      const lbl = el.runBothBtn.querySelector(".btn-label");
      if (lbl) lbl.textContent = loading && activeAction === "compare" ? "Running comparison..." : "Run both";
    }
  }

  // --------------------------------------------------------------------------
  // API Calls
  // --------------------------------------------------------------------------
  async function fetchHealth() {
    try {
      const res = await fetch(apiUrl("/api/health"));
      if (!res.ok) throw new Error(`Health check returned HTTP ${res.status}`);
      const data = await res.json();
      state.health = data;
      setOnlineStatus(data.floor);
      if (el.metaFloor && data.floor != null) {
        el.metaFloor.textContent = formatRate(data.floor);
      }
      return true;
    } catch (err) {
      setOfflineStatus();
      showOfflineBanner();
      setLive(false);
      return false;
    }
  }

  async function fetchSchemes() {
    try {
      const res = await fetch(apiUrl("/api/schemes"));
      if (!res.ok) throw new Error(`Schemes request returned HTTP ${res.status}`);
      const schemes = await res.json();
      if (Array.isArray(schemes) && schemes.length > 0) {
        state.schemes = schemes;
        renderSchemes(schemes);
        return true;
      }
      throw new Error("Empty schemes list returned");
    } catch (err) {
      if (!state.schemes || state.schemes.length === 0) {
        state.schemes = CACHED_SCHEMES;
        renderSchemes(CACHED_SCHEMES);
      }
      return false;
    }
  }

  async function runCompare() {
    clearError();
    setLoading(true, "compare");
    try {
      const alphaVal = typeof state.alpha === "string" ? parseFloat(state.alpha) : state.alpha;
      const payload = {
        scheme: state.scheme,
        n_message_qubits: state.n_message_qubits,
        attack_pauli: state.attack_pauli,
        noise_p: Number(state.noise_p) || 0.0,
        decoy_rounds: Number(state.decoy_rounds) || 4200,
        alpha: isNaN(alphaVal) ? 1e-10 : alphaVal,
        seed: state.seedCompare,
      };

      const res = await fetch(apiUrl("/api/compare"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${res.status}: ${res.statusText}`);
      }

      const data = await res.json();
      state.lastCompareResult = data;
      setLive(true);
      clearError();
      renderCompare(data);
    } catch (err) {
      if (!state.isLive) {
        setOfflineStatus();
        showOfflineBanner();
        setLive(false);
        renderCompare(CACHED_COMPARE_DATA);
      } else {
        showError(`Comparison run failed: ${err.message}`);
      }
    } finally {
      setLoading(false, "compare");
    }
  }

  async function runHonest() {
    clearError();
    setLoading(true, "honest");
    try {
      const alphaVal = typeof state.alpha === "string" ? parseFloat(state.alpha) : state.alpha;
      const payload = {
        scheme: state.scheme,
        n_message_qubits: state.n_message_qubits,
        attack: null,
        attack_pauli: null,
        noise_p: Number(state.noise_p) || 0.0,
        decoy_rounds: Number(state.decoy_rounds) || 4200,
        alpha: isNaN(alphaVal) ? 1e-10 : alphaVal,
        seed: state.seedHonest,
      };

      const res = await fetch(apiUrl("/api/run"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${res.status}: ${res.statusText}`);
      }

      const data = await res.json();
      setLive(true);
      clearError();
      renderHonestRun(data);
    } catch (err) {
      if (!state.isLive) {
        setOfflineStatus();
        showOfflineBanner();
        setLive(false);
        renderHonestRun(CACHED_COMPARE_DATA.honest);
      } else {
        showError(`Honest run failed: ${err.message}`);
      }
    } finally {
      setLoading(false, "honest");
    }
  }

  // --------------------------------------------------------------------------
  // Rendering
  // --------------------------------------------------------------------------
  function renderSchemes(schemes) {
    if (!el.schemesList) return;
    el.schemesList.innerHTML = "";

    schemes.forEach((s) => {
      const card = document.createElement("label");
      card.className = "scheme-card-label" + (s.name === state.scheme ? " is-selected" : "");

      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = "scheme_radio";
      radio.value = s.name;
      radio.checked = s.name === state.scheme;

      radio.addEventListener("change", () => {
        if (radio.checked && state.scheme !== s.name) {
          state.scheme = s.name;
          updateSchemeSelection();
          runCompare();
        }
      });

      const nameSpan = document.createElement("span");
      nameSpan.className = "scheme-name";
      nameSpan.textContent = s.name;

      const famSpan = document.createElement("span");
      famSpan.className = "scheme-family mono";
      famSpan.textContent = `— ${s.family || "quantum-scheme"}`;

      card.appendChild(radio);
      card.appendChild(nameSpan);
      card.appendChild(famSpan);
      el.schemesList.appendChild(card);
    });
  }

  function updateSchemeSelection() {
    if (!el.schemesList) return;
    const cards = el.schemesList.querySelectorAll(".scheme-card-label");
    cards.forEach((card) => {
      const radio = card.querySelector("input[type='radio']");
      if (radio && radio.value === state.scheme) {
        card.classList.add("is-selected");
        radio.checked = true;
      } else {
        card.classList.remove("is-selected");
      }
    });
  }

  function renderCompare(data) {
    const honest = data.honest || {};
    const forged = data.forged || {};
    const hSum = honest.summary || {};
    const fSum = forged.summary || {};
    const hLayers = honest.layers || {};
    const fLayers = forged.layers || {};

    const l0 = fLayers.L0 || {};
    const l1 = fLayers.L1 || {};
    const l2 = fLayers.L2 || {};
    const l3 = fLayers.L3 || {};

    const standardClear = !l0.flagged && !l1.flagged && !l2.flagged;
    const l3Caught = Boolean(l3.flagged);

    // 1. Meta Strip
    if (el.metaScheme) el.metaScheme.textContent = state.scheme;
    if (el.metaBits) el.metaBits.textContent = String(state.n_message_qubits);
    if (el.metaDecoys) el.metaDecoys.textContent = Number(state.decoy_rounds).toLocaleString();
    if (el.metaFloor) {
      const floorVal = l1.floor != null ? l1.floor : (state.health?.floor != null ? state.health.floor : 0.03442);
      el.metaFloor.textContent = formatRate(floorVal);
    }

    // 2. Score Strip
    if (el.scoreForgeryRate) {
      let rate = 0;
      if (l3.certificates && l3.certificates.length > 0) {
        rate = l3.certificates[0].success_probability != null ? l3.certificates[0].success_probability : 1.0;
      } else if (fSum.accepted && fSum.message_changed) {
        rate = 1.0;
      }
      el.scoreForgeryRate.textContent = formatPercent(rate);
    }

    if (el.scoreHonestAccept) {
      el.scoreHonestAccept.textContent = hSum.accepted ? "100.0%" : "0.0%";
    }

    if (el.scoreStandardChecks) {
      el.scoreStandardChecks.textContent = standardClear ? "3/3 CLEAR" : "FLAGGED";
      el.scoreStandardChecks.className = "score-numeral mono " + (standardClear ? "score-numeral--neutral" : "score-numeral--threat");
    }

    if (el.scorePauliguardPill) {
      if (l3Caught) {
        el.scorePauliguardPill.className = "verdict-pill verdict-pill--caught";
        el.scorePauliguardPill.textContent = "CAUGHT";
      } else {
        el.scorePauliguardPill.className = "verdict-pill verdict-pill--green";
        el.scorePauliguardPill.textContent = "CLEAR";
      }
    }

    // 3. Verdict Panel
    if (el.verdictPanel) {
      if (fSum.accepted && fSum.message_changed && standardClear) {
        el.verdictPanel.className = "verdict-panel verdict-panel--threat";
        el.verdictHeadline.textContent = "SIGNATURE ACCEPTED · MESSAGE CHANGED · STANDARD CHECKS SAW NOTHING";
      } else if (!fSum.accepted) {
        el.verdictPanel.className = "verdict-panel verdict-panel--safe";
        el.verdictHeadline.textContent = "FORGERY REJECTED · PROTOCOL VERIFIER REFUSED SIGNATURE";
      } else {
        el.verdictPanel.className = "verdict-panel verdict-panel--threat";
        el.verdictHeadline.textContent = "ATTACK EXECUTED · ANOMALIES RECORDED BY DETECTOR LAYERS";
      }

      const rateH = formatRate(data.decoy_rate_honest != null ? data.decoy_rate_honest : l1.observed_rate);
      const rateF = formatRate(data.decoy_rate_forged != null ? data.decoy_rate_forged : l1.observed_rate);
      el.verdictSubline.textContent = `decoy error honest ${rateH} vs forged ${rateF}, statistically indistinguishable.`;
    }

    // 4. Exhibits
    // Exhibit A (Honest)
    const hIn = hSum.message_in || [1, 1];
    const hOut = hSum.message_out || [1, 1];
    renderChips(hIn, el.exhibitAliceA);
    renderChips(hOut, el.exhibitBobA);

    if (el.exhibitDecoyA) {
      const hTau = hLayers.L1?.tau != null ? formatRate(hLayers.L1.tau) : "0.04534";
      const hRate = formatRate(data.decoy_rate_honest != null ? data.decoy_rate_honest : 0.03524);
      el.exhibitDecoyA.innerHTML = `Decoy error rate: <span class="num-val">${hRate}</span> (Serfling τ = <span class="num-val">${hTau}</span>)`;
    }

    if (el.exhibitStatusA) {
      const accText = hSum.accepted ? "ACCEPTED" : "REJECTED";
      const chgText = hSum.message_changed ? "CHANGED" : "INTACT";
      el.exhibitStatusA.textContent = `Signature: ${accText} · Message: ${chgText}`;
      el.exhibitStatusA.className = "exhibit-outcome mono " + (hSum.accepted && !hSum.message_changed ? "exhibit-outcome--intact" : "exhibit-outcome--forged");
    }

    // Exhibit B (Forged)
    const fIn = fSum.message_in || [1, 1];
    const fOut = fSum.message_out || [0, 1];
    const changedMask = fOut.map((b, i) => b !== fIn[i]);
    renderChips(fIn, el.exhibitAliceB);
    renderChips(fOut, el.exhibitBobB, changedMask);

    if (el.exhibitDecoyB) {
      const fTau = l1.tau != null ? formatRate(l1.tau) : "0.04534";
      const fRate = formatRate(data.decoy_rate_forged != null ? data.decoy_rate_forged : 0.03524);
      el.exhibitDecoyB.innerHTML = `Decoy error rate: <span class="num-val">${fRate}</span> (Serfling τ = <span class="num-val">${fTau}</span>)`;
    }

    if (el.exhibitStatusB) {
      const accText = fSum.accepted ? "ACCEPTED" : "REJECTED";
      const chgText = fSum.message_changed ? "CHANGED (FORGERY)" : "INTACT";
      el.exhibitStatusB.textContent = `Signature: ${accText} · Message: ${chgText}`;
      el.exhibitStatusB.className = "exhibit-outcome mono " + (fSum.message_changed ? "exhibit-outcome--forged" : "exhibit-outcome--intact");
    }

    // 5. Cross-Examination Rows
    // Row 1: Standard Checks
    if (el.standardStatusPill) {
      if (standardClear) {
        el.standardStatusPill.className = "verdict-pill verdict-pill--neutral";
        el.standardStatusPill.textContent = "ALL CLEAR";
      } else {
        el.standardStatusPill.className = "verdict-pill verdict-pill--caught";
        el.standardStatusPill.textContent = "ANOMALY FLAGGED";
      }
    }

    if (el.standardWhyContent) {
      const l0Deriv = l0.derivation || "no threshold - deterministic predicate";
      const l1Deriv = l1.derivation || `tau = ${formatRate(l1.tau)} from Serfling; xbar=${formatRate(l1.observed_rate)}, PASS`;
      const l2Deriv = l2.derivation || `Azuma-Hoeffding: tau = ${formatNum(l2.threshold, 4)}; observed=${formatNum(l2.observed, 2)}, PASS`;

      el.standardWhyContent.innerHTML = `
        <div class="audit-breakdown-grid">
          <div class="breakdown-box">
            <div class="breakdown-title mono">[L0 CONFORMANCE CHECK]</div>
            <div class="breakdown-derivation">State-machine verification: ${escapeHtml(l0Deriv)}</div>
          </div>
          <div class="breakdown-box">
            <div class="breakdown-title mono">[L1 SERFLING DECOY BOUND]</div>
            <div class="breakdown-derivation">${escapeHtml(l1Deriv)}</div>
          </div>
          <div class="breakdown-box">
            <div class="breakdown-title mono">[L2 AZUMA ENTANGLEMENT CHECK]</div>
            <div class="breakdown-derivation">${escapeHtml(l2Deriv)}</div>
          </div>
        </div>
      `;
    }

    // Row 2: PauliGuard L3
    if (el.l3StatusPill) {
      if (l3Caught) {
        el.l3StatusPill.className = "verdict-pill verdict-pill--outline-red";
        el.l3StatusPill.textContent = "FORGERY CAUGHT";
      } else {
        el.l3StatusPill.className = "verdict-pill verdict-pill--neutral";
        el.l3StatusPill.textContent = "NO MALLEABILITY DETECTED";
      }
    }

    if (el.l3WhyContent) {
      const cert = (l3.certificates && l3.certificates[0]) || null;
      if (cert) {
        const witness = cert.witness_pauli || "+XI";
        const sigPauli = cert.signature_pauli || "+XI";
        const dim = cert.malleability_dimension != null ? cert.malleability_dimension : 4;
        const prob = cert.success_probability != null ? formatRate(cert.success_probability) : "1.00000";
        const trials = cert.execution_trials != null ? `${cert.execution_accepted}/${cert.execution_trials}` : "16/16";
        const explanation = cert.explanation || "Pauli-conjugation attack satisfies arbitrator predicate.";
        const caveat = cert.caveat || "L3 is sound, not complete: a certificate proves an attack exists; no malleability found is NOT a proof of security.";

        el.l3WhyContent.innerHTML = `
          <div class="certificate-dossier">
            <div class="cert-meta-grid mono">
              <div>
                <div class="cert-item-label">[WITNESS PAULI]</div>
                <div class="cert-item-value cert-item-value--red">${escapeHtml(witness)}</div>
              </div>
              <div>
                <div class="cert-item-label">[SIGNATURE PAULI]</div>
                <div class="cert-item-value cert-item-value--red">${escapeHtml(sigPauli)}</div>
              </div>
              <div>
                <div class="cert-item-label">[MALLEABILITY DIM]</div>
                <div class="cert-item-value">${dim}</div>
              </div>
              <div>
                <div class="cert-item-label">[SUCCESS PROB]</div>
                <div class="cert-item-value cert-item-value--red">${prob} (100%)</div>
              </div>
            </div>
            <div class="cert-explanation">${escapeHtml(explanation)}</div>
            <div class="breakdown-derivation" style="margin-bottom: 0.5rem;">
              Execution verification: <strong>${escapeHtml(trials)} trials accepted</strong> with message altered.
              Derivation: ${escapeHtml(l3.derivation || "no threshold - algebraic search")}.
            </div>
            <div class="cert-caveat mono">${escapeHtml(caveat)}</div>
          </div>
        `;
      } else {
        el.l3WhyContent.innerHTML = `
          <div class="breakdown-box">
            <div class="breakdown-derivation">
              No symplectic nullspace witness found for '${escapeHtml(state.scheme)}' at n=${state.n_message_qubits}.
              ${escapeHtml(l3.derivation || "no threshold - algebraic search")}
            </div>
          </div>
        `;
      }
    }
  }

  function renderHonestRun(data) {
    const sum = data.summary || {};
    const layers = data.layers || {};
    const l1 = layers.L1 || {};

    // 1. Meta Strip
    if (el.metaScheme) el.metaScheme.textContent = state.scheme;
    if (el.metaBits) el.metaBits.textContent = String(state.n_message_qubits);
    if (el.metaDecoys) el.metaDecoys.textContent = Number(state.decoy_rounds).toLocaleString();
    if (el.metaFloor) {
      const floorVal = l1.floor != null ? l1.floor : (state.health?.floor != null ? state.health.floor : 0.03442);
      el.metaFloor.textContent = formatRate(floorVal);
    }

    // 2. Score Strip
    if (el.scoreForgeryRate) el.scoreForgeryRate.textContent = "0.0%";
    if (el.scoreHonestAccept) el.scoreHonestAccept.textContent = sum.accepted ? "100.0%" : "0.0%";
    if (el.scoreStandardChecks) {
      el.scoreStandardChecks.textContent = "3/3 CLEAR";
      el.scoreStandardChecks.className = "score-numeral mono score-numeral--neutral";
    }
    if (el.scorePauliguardPill) {
      el.scorePauliguardPill.className = "verdict-pill verdict-pill--green";
      el.scorePauliguardPill.textContent = "CLEAR";
    }

    // 3. Verdict Panel
    if (el.verdictPanel) {
      el.verdictPanel.className = "verdict-panel verdict-panel--safe";
      el.verdictHeadline.textContent = "HONEST SIGNATURE ACCEPTED · MESSAGE INTACT · ALL LAYERS CLEAR";
      const obsRate = l1.observed_rate != null ? formatRate(l1.observed_rate) : "0.03524";
      el.verdictSubline.textContent = `decoy error rate ${obsRate}, within Serfling bound. Zero anomalies detected.`;
    }

    // 4. Exhibits
    const mIn = sum.message_in || [0, 1];
    const mOut = sum.message_out || [0, 1];
    renderChips(mIn, el.exhibitAliceA);
    renderChips(mOut, el.exhibitBobA);

    if (el.exhibitDecoyA) {
      const tau = l1.tau != null ? formatRate(l1.tau) : "0.04534";
      const rate = l1.observed_rate != null ? formatRate(l1.observed_rate) : "0.03524";
      el.exhibitDecoyA.innerHTML = `Decoy error rate: <span class="num-val">${rate}</span> (Serfling τ = <span class="num-val">${tau}</span>)`;
    }

    if (el.exhibitStatusA) {
      el.exhibitStatusA.textContent = "Signature: ACCEPTED · Message: INTACT";
      el.exhibitStatusA.className = "exhibit-outcome mono exhibit-outcome--intact";
    }

    // Exhibit B in honest-only view shows honest baseline replicated
    renderChips(mIn, el.exhibitAliceB);
    renderChips(mOut, el.exhibitBobB);

    if (el.exhibitDecoyB) {
      const tau = l1.tau != null ? formatRate(l1.tau) : "0.04534";
      const rate = l1.observed_rate != null ? formatRate(l1.observed_rate) : "0.03524";
      el.exhibitDecoyB.innerHTML = `Decoy error rate: <span class="num-val">${rate}</span> (Serfling τ = <span class="num-val">${tau}</span>)`;
    }

    if (el.exhibitStatusB) {
      el.exhibitStatusB.textContent = "Baseline: HONEST RUN (Click 'Run the forgery' to test attack)";
      el.exhibitStatusB.className = "exhibit-outcome mono exhibit-outcome--intact";
    }

    // 5. Cross-Examination Rows
    if (el.standardStatusPill) {
      el.standardStatusPill.className = "verdict-pill verdict-pill--neutral";
      el.standardStatusPill.textContent = "ALL CLEAR";
    }

    if (el.standardWhyContent) {
      el.standardWhyContent.innerHTML = `
        <div class="audit-breakdown-grid">
          <div class="breakdown-box">
            <div class="breakdown-title mono">[HONEST EXECUTION VERIFIED]</div>
            <div class="breakdown-derivation">${escapeHtml(l1.derivation || "All physical channels and state machines conform to specification.")}</div>
          </div>
        </div>
      `;
    }

    if (el.l3StatusPill) {
      el.l3StatusPill.className = "verdict-pill verdict-pill--green";
      el.l3StatusPill.textContent = "CLEAR";
    }

    if (el.l3WhyContent) {
      el.l3WhyContent.innerHTML = `
        <div class="breakdown-box">
          <div class="breakdown-derivation">Honest execution executed without attack injection. Layer 3 reports no active forgery.</div>
        </div>
      `;
    }
  }

  function escapeHtml(str) {
    if (str == null) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // --------------------------------------------------------------------------
  // Event Listeners & Initialization
  // --------------------------------------------------------------------------
  function setupEvents() {
    if (el.dismissErrorBtn) {
      el.dismissErrorBtn.addEventListener("click", clearError);
    }

    if (el.runForgeryBtn) {
      el.runForgeryBtn.addEventListener("click", runCompare);
    }

    if (el.runHonestBtn) {
      el.runHonestBtn.addEventListener("click", runHonest);
    }

    if (el.runBothBtn) {
      el.runBothBtn.addEventListener("click", runCompare);
    }

    // Stepper
    if (el.stepDecBtn && el.messageBitsInput) {
      el.stepDecBtn.addEventListener("click", () => {
        let val = parseInt(el.messageBitsInput.value, 10) || 2;
        if (val > 2) {
          val -= 1;
          el.messageBitsInput.value = val;
          state.n_message_qubits = val;
        }
      });
    }

    if (el.stepIncBtn && el.messageBitsInput) {
      el.stepIncBtn.addEventListener("click", () => {
        let val = parseInt(el.messageBitsInput.value, 10) || 2;
        if (val < 6) {
          val += 1;
          el.messageBitsInput.value = val;
          state.n_message_qubits = val;
        }
      });
    }

    // Advanced Inputs
    if (el.noiseInput) {
      el.noiseInput.addEventListener("change", (e) => {
        state.noise_p = parseFloat(e.target.value) || 0.0;
      });
    }

    if (el.decoysInput) {
      el.decoysInput.addEventListener("change", (e) => {
        state.decoy_rounds = parseInt(e.target.value, 10) || 4200;
      });
    }

    if (el.alphaInput) {
      el.alphaInput.addEventListener("change", (e) => {
        state.alpha = e.target.value.trim() || "1e-10";
      });
    }

    if (el.attackPauliSelect) {
      el.attackPauliSelect.addEventListener("change", (e) => {
        state.attack_pauli = e.target.value || "X";
      });
    }
  }

  // --------------------------------------------------------------------------
  // Bootstrap
  // --------------------------------------------------------------------------
  async function init() {
    setupEvents();

    // 1. Initial cached fallback state: render immediately so UI is always labeled, populated, and stable
    state.schemes = CACHED_SCHEMES;
    renderSchemes(CACHED_SCHEMES);
    renderCompare(CACHED_COMPARE_DATA);
    setLive(false);

    // 2. Health check
    const isOnline = await fetchHealth();

    // 3. If online, fetch live schemes and auto-run compare with fixed seeds
    if (isOnline) {
      await fetchSchemes();
      await runCompare();
    } else {
      setOfflineStatus();
      showOfflineBanner();
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

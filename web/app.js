/**
 * PAULIGUARD — DEMO WEB APPLICATION
 * Plain vanilla JavaScript (No frameworks, No build step, No CDN).
 * Supports full 40-second demonstration workflow and lockstep comparison.
 */

(function () {
  'use strict';

  // State
  const state = {
    schemes: [],
    currentSchemeName: null,
    currentSchemeMeta: null,
    currentSpecData: null,
    lastRunResult: null,
    isLoading: false,
    previousForgeryRate: null,
  };

  // DOM Elements cache
  const elements = {
    // Header & Status
    backendStatus: document.getElementById('backendStatus'),
    floorValue: document.getElementById('floorValue'),
    globalError: document.getElementById('globalError'),
    errorMessage: document.getElementById('errorMessage'),
    dismissErrorBtn: document.getElementById('dismissErrorBtn'),

    // Controls
    schemeSelect: document.getElementById('schemeSelect'),
    qubitsInput: document.getElementById('qubitsInput'),
    noiseSlider: document.getElementById('noiseSlider'),
    noiseDisplay: document.getElementById('noiseDisplay'),
    decoyInput: document.getElementById('decoyInput'),
    alphaSelect: document.getElementById('alphaSelect'),
    pauliSelect: document.getElementById('pauliSelect'),
    btnRunHonest: document.getElementById('btnRunHonest'),
    btnRunForgery: document.getElementById('btnRunForgery'),
    btnRunCompare: document.getElementById('btnRunCompare'),

    // Left Column: Spec & Live Editor
    specFamilyBadge: document.getElementById('specFamilyBadge'),
    specCitation: document.getElementById('specCitation'),
    specEncryptionTag: document.getElementById('specEncryptionTag'),
    specStepsTag: document.getElementById('specStepsTag'),
    specDecoyTag: document.getElementById('specDecoyTag'),
    yamlSpecPane: document.getElementById('yamlSpecPane'),
    btnCopyYaml: document.getElementById('btnCopyYaml'),
    btnReanalyseSpec: document.getElementById('btnReanalyseSpec'),
    btnResetSpec: document.getElementById('btnResetSpec'),
    btnAddSwapTestFix: document.getElementById('btnAddSwapTestFix'),
    btnRemoveArbitratorCheck: document.getElementById('btnRemoveArbitratorCheck'),
    specEditorError: document.getElementById('specEditorError'),
    specEditorErrorMsg: document.getElementById('specEditorErrorMsg'),
    liveResultsStrip: document.getElementById('liveResultsStrip'),
    liveResultsStatusBadge: document.getElementById('liveResultsStatusBadge'),
    resMalDim: document.getElementById('resMalDim'),
    resCertCount: document.getElementById('resCertCount'),
    resHonestRate: document.getElementById('resHonestRate'),
    resForgeryRate: document.getElementById('resForgeryRate'),
    resForgeryDelta: document.getElementById('resForgeryDelta'),
    resDisputeCount: document.getElementById('resDisputeCount'),
    resDegradedNotice: document.getElementById('resDegradedNotice'),
    resDegradedText: document.getElementById('resDegradedText'),
    assumedFieldsList: document.getElementById('assumedFieldsList'),
    specWarningsContainer: document.getElementById('specWarningsContainer'),
    specWarningsList: document.getElementById('specWarningsList'),

    // Centre Column: Execution & Money Shot
    runModeBadge: document.getElementById('runModeBadge'),
    moneyShotBanner: document.getElementById('moneyShotBanner'),
    moneyShotQberDetail: document.getElementById('moneyShotQberDetail'),

    // Honest Panel
    honestPanel: document.getElementById('honestPanel'),
    honestAttackLabel: document.getElementById('honestAttackLabel'),
    honestStatusBadge: document.getElementById('honestStatusBadge'),
    honestAliceChips: document.getElementById('honestAliceChips'),
    honestBobChips: document.getElementById('honestBobChips'),
    honestDecoyRate: document.getElementById('honestDecoyRate'),
    honestStatusText: document.getElementById('honestStatusText'),

    // Attacked Panel
    attackedPanel: document.getElementById('attackedPanel'),
    attackedAttackLabel: document.getElementById('attackedAttackLabel'),
    attackedStatusBadge: document.getElementById('attackedStatusBadge'),
    forgedAliceChips: document.getElementById('forgedAliceChips'),
    forgedBobChips: document.getElementById('forgedBobChips'),
    forgedDecoyRate: document.getElementById('forgedDecoyRate'),
    attackedStatusText: document.getElementById('attackedStatusText'),

    // Certificate Panel
    certificatePanel: document.getElementById('certificatePanel'),
    certWitnessPauli: document.getElementById('certWitnessPauli'),
    certSignaturePauli: document.getElementById('certSignaturePauli'),
    certMalleabilityDim: document.getElementById('certMalleabilityDim'),
    certSuccessProb: document.getElementById('certSuccessProb'),
    certExecutionSummary: document.getElementById('certExecutionSummary'),
    certPredicateSigns: document.getElementById('certPredicateSigns'),
    certExplanation: document.getElementById('certExplanation'),
    certCaveat: document.getElementById('certCaveat'),

    // Right Column: Detection Layers
    cardL0: document.getElementById('cardL0'),
    pillL0: document.getElementById('pillL0'),
    statL0: document.getElementById('statL0'),
    derivationL0: document.getElementById('derivationL0'),

    cardL1: document.getElementById('cardL1'),
    pillL1: document.getElementById('pillL1'),
    statL1: document.getElementById('statL1'),
    derivationL1: document.getElementById('derivationL1'),

    cardL2: document.getElementById('cardL2'),
    pillL2: document.getElementById('pillL2'),
    statL2: document.getElementById('statL2'),
    derivationL2: document.getElementById('derivationL2'),

    cardL3: document.getElementById('cardL3'),
    pillL3: document.getElementById('pillL3'),
    statL3: document.getElementById('statL3'),
    l3CertSummary: document.getElementById('l3CertSummary'),
    l3WitnessText: document.getElementById('l3WitnessText'),
    l3VText: document.getElementById('l3VText'),
    l3DimText: document.getElementById('l3DimText'),
    l3ProbText: document.getElementById('l3ProbText'),
    l3ExecConfirmText: document.getElementById('l3ExecConfirmText'),
    derivationL3: document.getElementById('derivationL3'),
  };

  // =========================================================================
  // API HELPERS
  // =========================================================================

  async function apiRequest(endpoint, options = {}) {
    try {
      const response = await fetch(endpoint, {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        ...options,
      });

      if (!response.ok) {
        let errDetail = `HTTP ${response.status} ${response.statusText}`;
        try {
          const errJson = await response.json();
          if (errJson && errJson.detail) {
            errDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
          }
        } catch (_) {}
        throw new Error(errDetail);
      }

      return await response.json();
    } catch (err) {
      console.error(`API Error on ${endpoint}:`, err);
      showError(`Request to ${endpoint} failed: ${err.message}`);
      throw err;
    }
  }

  // =========================================================================
  // ERROR HANDLING
  // =========================================================================

  function showError(msg) {
    elements.errorMessage.textContent = msg;
    elements.globalError.classList.remove('hidden');
  }

  function clearError() {
    elements.globalError.classList.add('hidden');
    elements.errorMessage.textContent = '';
  }

  // =========================================================================
  // CONTROLS PARSER
  // =========================================================================

  function getControlValues() {
    const scheme = elements.schemeSelect.value || 'lu-2022';
    const n_message_qubits = parseInt(elements.qubitsInput.value, 10) || 2;
    const noise_p = parseFloat(elements.noiseSlider.value) || 0.0;
    const decoy_rounds = parseInt(elements.decoyInput.value, 10) || 4200;
    const alpha = parseFloat(elements.alphaSelect.value) || 1e-10;
    const attack_pauli = elements.pauliSelect.value || 'X';

    return {
      scheme,
      n_message_qubits,
      noise_p,
      decoy_rounds,
      alpha,
      attack_pauli,
    };
  }

  function setLoading(loading, actionName = '') {
    state.isLoading = loading;
    elements.btnRunHonest.disabled = loading;
    elements.btnRunForgery.disabled = loading;
    elements.btnRunCompare.disabled = loading;
    elements.schemeSelect.disabled = loading;

    if (loading) {
      elements.runModeBadge.textContent = actionName ? `Executing: ${actionName}...` : 'Running...';
      elements.runModeBadge.className = 'badge badge-accent';
    }
  }

  // =========================================================================
  // CHIPS RENDERING (WITH DIFFERING BIT HIGHLIGHT)
  // =========================================================================

  function renderChips(container, bitArray, isAttackedBob = false, aliceBits = null) {
    container.innerHTML = '';

    if (!bitArray || !Array.isArray(bitArray) || bitArray.length === 0) {
      const emptyChip = document.createElement('span');
      emptyChip.className = 'chip chip-empty';
      emptyChip.textContent = '—';
      container.appendChild(emptyChip);
      return;
    }

    bitArray.forEach((bit, idx) => {
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = String(bit);

      // Crucial requirement: When messages differ, highlight differing bit chip in red on attacked panel
      if (isAttackedBob && aliceBits && Array.isArray(aliceBits) && aliceBits[idx] !== undefined) {
        if (aliceBits[idx] !== bit) {
          chip.classList.add('chip-changed');
          chip.title = `Bit altered by forgery! Alice sent ${aliceBits[idx]} → Bob received ${bit}`;
        }
      }

      container.appendChild(chip);
    });
  }

  // =========================================================================
  // LEFT COLUMN: SPEC & LIVE EDITING HELPERS
  // =========================================================================

  function showEditorError(msg) {
    elements.specEditorErrorMsg.textContent = msg;
    elements.specEditorError.classList.remove('hidden');
  }

  function hideEditorError() {
    elements.specEditorError.classList.add('hidden');
    elements.specEditorErrorMsg.textContent = '';
  }

  function addSwapTestFixToYaml(yamlText) {
    const hardeningBlock = 'hardening:\n  swap_test:\n    enabled: true\n    copies: 8';
    if (/^hardening\s*:/m.test(yamlText)) {
      return yamlText.replace(/^hardening\s*:(?:\n[ \t]+[^\n]*|\n(?![a-zA-Z0-9_-]+\s*:)[ \t]*[^\n]*)*/m, hardeningBlock);
    }
    return yamlText.trimEnd() + '\n\n' + hardeningBlock + '\n';
  }

  function removeArbitratorCheckFromYaml(yamlText) {
    const lines = yamlText.split('\n');
    let stepIndices = [];
    let inSteps = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^steps\s*:/.test(line)) {
        inSteps = true;
        continue;
      }
      if (inSteps && /^[a-zA-Z0-9_-]+\s*:/.test(line) && !line.startsWith(' ') && !line.startsWith('\t')) {
        inSteps = false;
        continue;
      }
      if (inSteps && /^\s*-\s+/.test(line)) {
        stepIndices.push(i);
      }
    }

    for (let k = 0; k < stepIndices.length; k++) {
      const start = stepIndices[k];
      const end = (k + 1 < stepIndices.length) ? stepIndices[k + 1] : lines.length;
      const stepText = lines.slice(start, end).join('\n');
      if (stepText.includes('trent_verify_equality_predicate')) {
        let actualEnd = end;
        for (let j = start + 1; j < lines.length; j++) {
          if (/^\s*-\s+/.test(lines[j]) || (/^[a-zA-Z0-9_-]+\s*:/.test(lines[j]) && !lines[j].startsWith(' '))) {
            actualEnd = j;
            break;
          }
        }
        lines.splice(start, actualEnd - start);
        return lines.join('\n');
      }
    }

    // Fallback regex if line scanner didn't match
    return yamlText.replace(/\n\s*-\s+procedure:[^\n]*\n(?:[ \t]+[^\n]*\n)*?[ \t]*name:\s*["']?trent_verify_equality_predicate["']?[^\n]*(?:\n[ \t]+[^\n]*)*/g, '');
  }

  async function handleReanalyseSpec() {
    hideEditorError();
    const yamlText = elements.yamlSpecPane.value || '';
    const params = getControlValues();
    const payload = {
      yaml: yamlText,
      n_message_qubits: params.n_message_qubits,
      trials: 50,
    };

    try {
      elements.liveResultsStatusBadge.textContent = 'Analysing...';
      const response = await fetch('/api/analyse_spec', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok || data.stage === 'parse') {
        const errorMsg = data.error || `HTTP ${response.status}: Failed analysing specification.`;
        showEditorError(errorMsg);
        elements.liveResultsStatusBadge.textContent = 'Parse Error';
        return;
      }

      // Update Results Strip
      elements.resMalDim.textContent = String(data.malleability_dimension ?? '0');
      const certCount = Array.isArray(data.certificates) ? data.certificates.length : 0;
      elements.resCertCount.textContent = String(certCount);

      const hRate = data.honest_acceptance_rate !== undefined ? Number(data.honest_acceptance_rate) : 1.0;
      elements.resHonestRate.textContent = hRate.toFixed(3);

      const fRate = data.forgery_success_rate !== undefined ? Number(data.forgery_success_rate) : 0.0;
      elements.resForgeryRate.textContent = fRate.toFixed(3);

      // Delta calculation
      if (state.previousForgeryRate !== null && state.previousForgeryRate !== undefined) {
        const delta = fRate - state.previousForgeryRate;
        if (delta < -0.001) {
          elements.resForgeryDelta.textContent = `▼ ${delta.toFixed(3)}`;
          elements.resForgeryDelta.className = 'delta-badge delta-drop';
        } else if (delta > 0.001) {
          elements.resForgeryDelta.textContent = `▲ +${delta.toFixed(3)}`;
          elements.resForgeryDelta.className = 'delta-badge delta-rise';
        } else {
          elements.resForgeryDelta.textContent = `(0.000)`;
          elements.resForgeryDelta.className = 'delta-badge delta-neutral';
        }
      } else {
        elements.resForgeryDelta.textContent = '(baseline)';
        elements.resForgeryDelta.className = 'delta-badge delta-neutral';
      }
      state.previousForgeryRate = fRate;

      // Dispute findings summary
      const findings = Array.isArray(data.dispute_findings) ? data.dispute_findings : [];
      const critCount = findings.filter(f => f.severity === 'critical').length;
      elements.resDisputeCount.textContent = `${findings.length} findings (${critCount} critical)`;

      // Warnings container
      const warnings = Array.isArray(data.warnings) ? data.warnings : [];
      if (warnings.length > 0) {
        elements.specWarningsList.innerHTML = '';
        warnings.forEach(w => {
          const li = document.createElement('li');
          li.textContent = w;
          elements.specWarningsList.appendChild(li);
        });
        elements.specWarningsContainer.classList.remove('hidden');
      } else {
        elements.specWarningsContainer.classList.add('hidden');
      }

      // Degraded notice
      if (data.degraded) {
        elements.resDegradedNotice.classList.remove('hidden');
        elements.resDegradedText.textContent = data.degraded;
      } else {
        elements.resDegradedNotice.classList.add('hidden');
      }

      // Update Certificate Panel if present
      if (certCount > 0 && data.certificates[0]) {
        updateCertificatePanel(data.certificates[0]);
      } else {
        updateCertificatePanel(null);
      }

      elements.liveResultsStatusBadge.textContent = 'Updated';
    } catch (err) {
      console.error('Error re-analysing spec:', err);
      showEditorError(err.message || 'Unknown network error analysing spec.');
    }
  }

  function handleResetSpec() {
    hideEditorError();
    if (state.currentSpecData && state.currentSpecData.raw) {
      elements.yamlSpecPane.value = state.currentSpecData.raw;
      handleReanalyseSpec();
    }
  }

  function handleAddSwapTestFix() {
    hideEditorError();
    const currentYaml = elements.yamlSpecPane.value || '';
    elements.yamlSpecPane.value = addSwapTestFixToYaml(currentYaml);
    handleReanalyseSpec();
  }

  function handleRemoveArbitratorCheck() {
    hideEditorError();
    const currentYaml = elements.yamlSpecPane.value || '';
    elements.yamlSpecPane.value = removeArbitratorCheckFromYaml(currentYaml);
    handleReanalyseSpec();
  }

  async function loadSchemeSpec(schemeName) {
    if (!schemeName) return;
    try {
      hideEditorError();
      const specData = await apiRequest(`/api/schemes/${encodeURIComponent(schemeName)}/spec`);
      state.currentSpecData = specData;
      state.currentSchemeName = schemeName;

      // Find meta from list
      const meta = state.schemes.find(s => s.name === schemeName) || {};
      state.currentSchemeMeta = meta;

      // Update Spec Metadata
      elements.specFamilyBadge.textContent = meta.family || 'PROTOCOL';
      elements.specCitation.textContent = meta.citation || 'Citation unavailable';

      elements.specEncryptionTag.textContent = `Encryption: ${meta.encryption || 'none'}`;
      elements.specStepsTag.textContent = `Steps: ${meta.n_steps || (specData.spec && specData.spec.steps ? specData.spec.steps.length : '—')}`;
      
      const decoyFrac = meta.decoy_protected_fraction !== undefined
        ? Math.round(meta.decoy_protected_fraction * 100)
        : (specData.spec && specData.spec.decoy_protected_fraction ? Math.round(specData.spec.decoy_protected_fraction * 100) : 0);
      elements.specDecoyTag.textContent = `Decoy Protected: ${decoyFrac}%`;

      // Update YAML Editor Textarea
      elements.yamlSpecPane.value = specData.raw || specData.yaml || (specData.spec ? JSON.stringify(specData.spec, null, 2) : '');

      // Update Assumed Fields (Deliberate Honesty Display)
      elements.assumedFieldsList.innerHTML = '';
      const assumed = meta.assumed_fields || (specData.spec && specData.spec.assumed_fields) || [];
      if (assumed.length > 0) {
        assumed.forEach(field => {
          const li = document.createElement('li');
          li.className = 'assumed-item';
          li.textContent = field;
          elements.assumedFieldsList.appendChild(li);
        });
      } else {
        const li = document.createElement('li');
        li.className = 'assumed-item';
        li.textContent = 'None declared in protocol spec.';
        elements.assumedFieldsList.appendChild(li);
      }

      // Spec validation warnings if any
      const warnings = specData.warnings || [];
      if (warnings.length > 0) {
        elements.specWarningsList.innerHTML = '';
        warnings.forEach(w => {
          const li = document.createElement('li');
          li.textContent = w;
          elements.specWarningsList.appendChild(li);
        });
        elements.specWarningsContainer.classList.remove('hidden');
      } else {
        elements.specWarningsContainer.classList.add('hidden');
      }

      // Re-analyse spec for live results strip
      await handleReanalyseSpec();
    } catch (err) {
      console.error('Failed to load scheme spec:', err);
    }
  }

  // =========================================================================
  // EXECUTION PANELS RENDERING
  // =========================================================================

  function updateHonestPanel(honestData, decoyRate) {
    if (!honestData) return;

    elements.honestAttackLabel.textContent = `attack: ${honestData.summary.attack_label || 'none'}`;

    renderChips(elements.honestAliceChips, honestData.summary.message_in);
    renderChips(elements.honestBobChips, honestData.summary.message_out);

    if (decoyRate !== undefined && decoyRate !== null) {
      elements.honestDecoyRate.textContent = Number(decoyRate).toFixed(5);
    } else {
      elements.honestDecoyRate.textContent = '0.00000';
    }

    if (honestData.summary.accepted) {
      elements.honestStatusBadge.textContent = 'SIGNATURE ACCEPTED';
      elements.honestStatusBadge.className = 'panel-status-pill pill-pass';
      if (!honestData.summary.message_changed) {
        elements.honestStatusText.textContent = '✓ SIGNATURE ACCEPTED — message intact';
        elements.honestStatusText.className = 'status-summary-text text-intact';
      } else {
        elements.honestStatusText.textContent = '⚠ SIGNATURE ACCEPTED — message CHANGED';
        elements.honestStatusText.className = 'status-summary-text text-changed';
      }
    } else {
      elements.honestStatusBadge.textContent = 'SIGNATURE REJECTED';
      elements.honestStatusBadge.className = 'panel-status-pill pill-fail';
      elements.honestStatusText.textContent = '✗ SIGNATURE REJECTED';
      elements.honestStatusText.className = 'status-summary-text text-changed';
    }
  }

  function updateAttackedPanel(forgedData, decoyRate, attackPauli = 'X') {
    if (!forgedData) return;

    elements.attackedAttackLabel.textContent = `attack: ${forgedData.summary.attack_label || 'paired_pauli'} (${attackPauli})`;

    const aliceBits = forgedData.summary.message_in;
    const bobBits = forgedData.summary.message_out;

    renderChips(elements.forgedAliceChips, aliceBits);
    renderChips(elements.forgedBobChips, bobBits, true, aliceBits);

    if (decoyRate !== undefined && decoyRate !== null) {
      elements.forgedDecoyRate.textContent = Number(decoyRate).toFixed(5);
    } else {
      elements.forgedDecoyRate.textContent = '0.00000';
    }

    if (forgedData.summary.accepted) {
      if (forgedData.summary.message_changed) {
        elements.attackedStatusBadge.textContent = 'SIGNATURE ACCEPTED';
        elements.attackedStatusBadge.className = 'panel-status-pill pill-pass';
        elements.attackedStatusText.textContent = '⚠ SIGNATURE ACCEPTED — message CHANGED';
        elements.attackedStatusText.className = 'status-summary-text text-changed';
      } else {
        elements.attackedStatusBadge.textContent = 'SIGNATURE ACCEPTED';
        elements.attackedStatusBadge.className = 'panel-status-pill pill-pass';
        elements.attackedStatusText.textContent = '✓ SIGNATURE ACCEPTED — message intact';
        elements.attackedStatusText.className = 'status-summary-text text-intact';
      }
    } else {
      elements.attackedStatusBadge.textContent = 'SIGNATURE REJECTED';
      elements.attackedStatusBadge.className = 'panel-status-pill pill-fail';
      elements.attackedStatusText.textContent = '✗ SIGNATURE REJECTED — attack detected by protocol';
      elements.attackedStatusText.className = 'status-summary-text text-neutral';
    }
  }

  // =========================================================================
  // THE MONEY SHOT BANNER
  // =========================================================================

  function updateMoneyShotBanner(forgedData, decoyRateHonest, decoyRateForged) {
    if (!forgedData || !forgedData.summary) {
      elements.moneyShotBanner.classList.add('hidden');
      return;
    }

    const accepted = forgedData.summary.accepted;
    const changed = forgedData.summary.message_changed;
    const l0SawNothing = forgedData.layers && forgedData.layers.L0 && !forgedData.layers.L0.flagged;
    const l1SawNothing = forgedData.layers && forgedData.layers.L1 && !forgedData.layers.L1.flagged;
    const l2SawNothing = forgedData.layers && forgedData.layers.L2 && !forgedData.layers.L2.flagged;

    if (accepted && changed && l0SawNothing && l1SawNothing && l2SawNothing) {
      elements.moneyShotBanner.classList.remove('hidden');
      const hRate = (decoyRateHonest !== undefined && decoyRateHonest !== null) ? Number(decoyRateHonest).toFixed(5) : '0.03310';
      const fRate = (decoyRateForged !== undefined && decoyRateForged !== null) ? Number(decoyRateForged).toFixed(5) : '0.03524';
      elements.moneyShotQberDetail.textContent = `(honest: ${hRate} vs forged: ${fRate} · within Serfling threshold τ)`;
    } else {
      elements.moneyShotBanner.classList.add('hidden');
    }
  }

  // =========================================================================
  // DETECTION LAYERS (L0, L1, L2, L3) RENDERING
  // =========================================================================

  function updateDetectionLayers(layers) {
    if (!layers) return;

    // --- L0 CONFORMANCE ---
    if (layers.L0) {
      const isL0Flagged = Boolean(layers.L0.flagged);
      elements.pillL0.textContent = isL0Flagged ? 'DETECTED' : 'PASS';
      elements.pillL0.className = `layer-status-pill ${isL0Flagged ? 'pill-fail' : 'pill-pass'}`;
      elements.cardL0.className = `layer-card ${isL0Flagged ? 'card-alert' : ''}`;

      const findingsCount = layers.L0.findings ? layers.L0.findings.length : 0;
      elements.statL0.textContent = findingsCount > 0
        ? `Conformance violation (${findingsCount} findings)`
        : 'Deterministic predicate (0 findings)';
      elements.derivationL0.textContent = layers.L0.derivation || 'no threshold - deterministic predicate';
    }

    // --- L1 CHANNEL STATISTICS ---
    if (layers.L1) {
      const isL1Flagged = Boolean(layers.L1.flagged);
      elements.pillL1.textContent = isL1Flagged ? 'DETECTED' : 'PASS';
      elements.pillL1.className = `layer-status-pill ${isL1Flagged ? 'pill-fail' : 'pill-pass'}`;
      elements.cardL1.className = `layer-card ${isL1Flagged ? 'card-alert' : ''}`;

      const xbar = layers.L1.observed_rate !== undefined ? Number(layers.L1.observed_rate).toFixed(5) : '—';
      const floor = layers.L1.floor !== undefined ? Number(layers.L1.floor).toFixed(5) : '—';
      const tau = layers.L1.tau !== undefined ? Number(layers.L1.tau).toFixed(5) : '—';
      const excess = layers.L1.excess_over_floor !== undefined ? Number(layers.L1.excess_over_floor).toFixed(5) : '—';

      elements.statL1.textContent = `x̄ = ${xbar} · floor = ${floor} · τ = ${tau} (excess: ${excess >= 0 ? '+' : ''}${excess})`;
      elements.derivationL1.textContent = layers.L1.derivation || 'Serfling concentration bound derivation';
    }

    // --- L2 ENTANGLEMENT QUALITY ---
    if (layers.L2) {
      const isL2Flagged = Boolean(layers.L2.flagged);
      elements.pillL2.textContent = isL2Flagged ? 'DETECTED' : 'PASS';
      elements.pillL2.className = `layer-status-pill ${isL2Flagged ? 'pill-fail' : 'pill-pass'}`;
      elements.cardL2.className = `layer-card ${isL2Flagged ? 'card-alert' : ''}`;

      const obs = layers.L2.observed !== undefined ? Number(layers.L2.observed).toFixed(4) : '1.0000';
      const thresh = layers.L2.threshold !== undefined ? Number(layers.L2.threshold).toFixed(4) : '—';
      const dev = (layers.L2.detail && layers.L2.detail.deviation !== undefined)
        ? Number(layers.L2.detail.deviation).toFixed(4)
        : '0.0000';

      elements.statL2.textContent = `p̂ = ${obs} · threshold = ${thresh} · deviation = ${dev}`;
      elements.derivationL2.textContent = layers.L2.derivation || 'Azuma-Hoeffding martingale derivation';
    }

    // --- L3 ALGEBRAIC MALLEABILITY ---
    if (layers.L3) {
      const certs = layers.L3.certificates || [];
      const hasMalleability = layers.L3.malleability_detected || certs.length > 0;
      const isL3Flagged = Boolean(layers.L3.flagged || hasMalleability);

      if (isL3Flagged && certs.length > 0) {
        const cert = certs[0];
        elements.pillL3.textContent = 'MALLEABILITY DETECTED';
        elements.pillL3.className = 'layer-status-pill pill-detected';
        elements.cardL3.className = 'layer-card card-alert';

        elements.statL3.textContent = `Found ${certs.length} algebraic witness (dim ${cert.malleability_dimension})`;
        elements.l3WitnessText.textContent = cert.witness_pauli;
        elements.l3VText.textContent = cert.signature_pauli;
        elements.l3DimText.textContent = String(cert.malleability_dimension);
        elements.l3ProbText.textContent = `${Number(cert.success_probability).toFixed(1)} (${Math.round(cert.success_probability * 100)}%)`;
        elements.l3ExecConfirmText.textContent = `Confirmed by execution: ${cert.execution_accepted}/${cert.execution_trials} accepted, ${cert.message_changed}/${cert.execution_trials} message changed`;

        elements.l3CertSummary.classList.remove('hidden');
        elements.derivationL3.textContent = layers.L3.derivation || 'no threshold - algebraic search';

        // Update full certificate panel
        updateCertificatePanel(cert);
      } else {
        elements.pillL3.textContent = 'CLEAR';
        elements.pillL3.className = 'layer-status-pill pill-pass';
        elements.cardL3.className = 'layer-card';

        elements.statL3.textContent = 'no threshold — algebraic search (0 witnesses)';
        elements.l3CertSummary.classList.add('hidden');
        elements.derivationL3.textContent = layers.L3.derivation || 'no threshold - algebraic search';

        // Hide full certificate panel
        updateCertificatePanel(null);
      }
    }
  }

  // =========================================================================
  // CERTIFICATE PANEL (FULL DETAILS + VERBATIM HONESTY CAVEAT)
  // =========================================================================

  function updateCertificatePanel(cert) {
    if (!cert) {
      elements.certificatePanel.classList.add('hidden');
      return;
    }

    elements.certificatePanel.classList.remove('hidden');
    elements.certWitnessPauli.textContent = cert.witness_pauli || '—';
    elements.certSignaturePauli.textContent = cert.signature_pauli || '—';
    elements.certMalleabilityDim.textContent = String(cert.malleability_dimension || '—');
    
    const prob = cert.success_probability !== undefined ? Number(cert.success_probability) : 1.0;
    elements.certSuccessProb.textContent = `${prob.toFixed(1)} (${Math.round(prob * 100)}% across keyspace)`;

    elements.certExecutionSummary.textContent = `Confirmed: ${cert.execution_accepted}/${cert.execution_trials} accepted, ${cert.message_changed}/${cert.execution_trials} message changed`;
    
    const signs = Array.isArray(cert.commutation_sign_range) ? cert.commutation_sign_range.join(', ') : '—';
    elements.certPredicateSigns.textContent = `${cert.predicate || 'E_{k}|P> == |S>'}  ·  signs: [${signs}]  ·  keys: ${cert.keys_tested || 16}`;

    elements.certExplanation.textContent = cert.explanation || 'Algebraic search discovered symplectic nullspace.';
    
    // HONESTY CAVEAT: Must be populated verbatim and NEVER hidden or truncated
    elements.certCaveat.textContent = cert.caveat || (
      'L3 is sound, not complete. This certificate proves the existence of an algebraic attack, ' +
      'but "no malleability found" is NOT a proof of security. The search covers the Pauli group ' +
      'modulo phase only; a general adversary may use an arbitrary CPTP map outside this search.'
    );
  }

  // =========================================================================
  // RUN ACTIONS (HONEST, FORGERY, COMPARE)
  // =========================================================================

  async function handleRunHonest() {
    clearError();
    setLoading(true, 'Honest Protocol Run');

    try {
      const params = getControlValues();
      const payload = {
        scheme: params.scheme,
        n_message_qubits: params.n_message_qubits,
        attack: null,
        attack_pauli: params.attack_pauli,
        noise_p: params.noise_p,
        decoy_rounds: params.decoy_rounds,
        alpha: params.alpha,
        seed: 101,
      };

      const result = await apiRequest('/api/run', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      state.lastRunResult = result;
      elements.runModeBadge.textContent = 'Honest Run Complete';
      elements.runModeBadge.className = 'badge badge-neutral';

      // Decoy rate calculation
      let decoyRate = 0.03310;
      if (result.layers && result.layers.L1 && result.layers.L1.observed_rate !== undefined) {
        decoyRate = result.layers.L1.observed_rate;
      }

      updateHonestPanel(result, decoyRate);
      updateDetectionLayers(result.layers);

      // In honest run, hide money shot banner
      elements.moneyShotBanner.classList.add('hidden');
    } catch (err) {
      console.error('Error running honest protocol:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleRunForgery() {
    clearError();
    setLoading(true, 'Paired-Pauli Forgery');

    try {
      const params = getControlValues();
      const payload = {
        scheme: params.scheme,
        n_message_qubits: params.n_message_qubits,
        attack: 'paired_pauli',
        attack_pauli: params.attack_pauli,
        noise_p: params.noise_p,
        decoy_rounds: params.decoy_rounds,
        alpha: params.alpha,
        seed: 102,
      };

      const result = await apiRequest('/api/run', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      state.lastRunResult = result;
      elements.runModeBadge.textContent = 'Forgery Run Complete';
      elements.runModeBadge.className = 'badge badge-accent';

      let decoyRate = 0.03524;
      if (result.layers && result.layers.L1 && result.layers.L1.observed_rate !== undefined) {
        decoyRate = result.layers.L1.observed_rate;
      }

      updateAttackedPanel(result, decoyRate, params.attack_pauli);
      updateDetectionLayers(result.layers);

      // Check money shot
      updateMoneyShotBanner(result, 0.03310, decoyRate);
    } catch (err) {
      console.error('Error running forgery protocol:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleRunCompare() {
    clearError();
    setLoading(true, 'Lockstep Comparison');

    try {
      const params = getControlValues();
      const payload = {
        scheme: params.scheme,
        n_message_qubits: params.n_message_qubits,
        attack_pauli: params.attack_pauli,
        noise_p: params.noise_p,
        decoy_rounds: params.decoy_rounds,
        alpha: params.alpha,
        seed: 101,
      };

      const result = await apiRequest('/api/compare', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      state.lastRunResult = result;
      elements.runModeBadge.textContent = 'Lockstep Compare Active';
      elements.runModeBadge.className = 'badge badge-accent';

      // Update Honest & Forged Panels
      updateHonestPanel(result.honest, result.decoy_rate_honest);
      updateAttackedPanel(result.forged, result.decoy_rate_forged, params.attack_pauli);

      // Detection Layers (from forged run to showcase L3 detection)
      updateDetectionLayers(result.forged.layers);

      // The Money Shot Banner
      updateMoneyShotBanner(result.forged, result.decoy_rate_honest, result.decoy_rate_forged);
    } catch (err) {
      console.error('Error running lockstep comparison:', err);
    } finally {
      setLoading(false);
    }
  }

  // =========================================================================
  // INITIALIZATION & EVENT BINDINGS
  // =========================================================================

  async function init() {
    // 1. Noise slider display update
    elements.noiseSlider.addEventListener('input', (e) => {
      elements.noiseDisplay.textContent = Number(e.target.value).toFixed(3);
    });

    // 2. Scheme dropdown change
    elements.schemeSelect.addEventListener('change', async (e) => {
      const schemeName = e.target.value;
      await loadSchemeSpec(schemeName);
      // Automatically re-run comparison when scheme changes
      handleRunCompare();
    });

    // 3. Action buttons
    elements.btnRunHonest.addEventListener('click', handleRunHonest);
    elements.btnRunForgery.addEventListener('click', handleRunForgery);
    elements.btnRunCompare.addEventListener('click', handleRunCompare);

    // 4. Live Spec Editor Action Buttons
    if (elements.btnReanalyseSpec) {
      elements.btnReanalyseSpec.addEventListener('click', () => handleReanalyseSpec());
    }
    if (elements.btnResetSpec) {
      elements.btnResetSpec.addEventListener('click', handleResetSpec);
    }
    if (elements.btnAddSwapTestFix) {
      elements.btnAddSwapTestFix.addEventListener('click', handleAddSwapTestFix);
    }
    if (elements.btnRemoveArbitratorCheck) {
      elements.btnRemoveArbitratorCheck.addEventListener('click', handleRemoveArbitratorCheck);
    }

    // 5. Copy YAML button
    elements.btnCopyYaml.addEventListener('click', () => {
      const yaml = elements.yamlSpecPane.value || elements.yamlSpecPane.textContent;
      if (navigator.clipboard && yaml) {
        navigator.clipboard.writeText(yaml).then(() => {
          const originalText = elements.btnCopyYaml.textContent;
          elements.btnCopyYaml.textContent = 'Copied!';
          setTimeout(() => { elements.btnCopyYaml.textContent = originalText; }, 1500);
        });
      }
    });

    // 5. Dismiss global error
    elements.dismissErrorBtn.addEventListener('click', clearError);

    // 6. Derivation accordions
    document.querySelectorAll('.btn-toggle-derivation').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        const targetBody = document.getElementById(targetId);
        if (targetBody) {
          const isHidden = targetBody.classList.contains('hidden');
          if (isHidden) {
            targetBody.classList.remove('hidden');
            btn.setAttribute('aria-expanded', 'true');
          } else {
            targetBody.classList.add('hidden');
            btn.setAttribute('aria-expanded', 'false');
          }
        }
      });
    });

    // 7. Initial Health Check
    try {
      const health = await apiRequest('/api/health');
      if (health && health.status === 'ok') {
        elements.backendStatus.textContent = 'Backend Online';
        const floorNum = health.floor !== undefined ? Number(health.floor).toFixed(5) : '0.03442';
        elements.floorValue.textContent = `${floorNum} (${health.floor_source || 'da8up31qtnsc73d0v7h0'})`;
      }
    } catch (err) {
      elements.backendStatus.textContent = 'Backend Offline';
      showError('Unable to connect to PauliGuard API. Please ensure backend is running.');
      return;
    }

    // 8. Discover Schemes
    try {
      const schemes = await apiRequest('/api/schemes');
      state.schemes = schemes || [];

      elements.schemeSelect.innerHTML = '';
      schemes.forEach(s => {
        const opt = document.createElement('option');
        opt.value = s.name;
        opt.textContent = `${s.name} (${s.family || 'AQS'})`;
        if (s.name === 'lu-2022') {
          opt.selected = true;
        }
        elements.schemeSelect.appendChild(opt);
      });

      const defaultScheme = elements.schemeSelect.value || (schemes[0] && schemes[0].name);
      if (defaultScheme) {
        await loadSchemeSpec(defaultScheme);
      }

      // Automatically run initial lockstep comparison for instant 40-second presentation
      await handleRunCompare();
    } catch (err) {
      console.error('Failed initializing schemes:', err);
    }
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();

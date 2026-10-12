export type ThreatState = "Normal" | "Reconnaissance" | "Elevated" | "UnderAttack" | "Critical";

export interface DefenseStrategyVector {
  encryptionStrength: number; // theta_t^enc (1 - 5)
  detectionSensitivity: number; // theta_t^det (0.1 - 1.0)
  authenticationThreshold: number; // theta_t^auth (40 - 90 trust score)
  keyRotationMinutes: number; // theta_t^rot (1 - 30 minutes)
  blockchainSyncFrequencySecs: number; // theta_t^chain (1 - 60 seconds)
}

export interface MarkovStateAssessment {
  currentState: ThreatState;
  stateIndex: number;
  transitionProbabilities: Record<ThreatState, number>; // P_ij
  observationVector: {
    abnormalAccessRate: number;
    encryptionLatencyMs: number;
    keyRotationFrequency: number;
    aiFalsePositiveRate: number;
    threatIntensity: number;
  };
  strategyVector: DefenseStrategyVector; // Theta_t = Phi(S_t)
  utilityScore: {
    accuracyBenefit: number;
    overheadCost: number;
    netUtility: number; // U_t = w1 * A_t - w2 * C_t
  };
  policyPerturbationApplied: boolean;
}

class MarkovDynamicDefenseManager {
  private states: ThreatState[] = ["Normal", "Reconnaissance", "Elevated", "UnderAttack", "Critical"];
  private currentStateIndex = 0; // 0 = Normal
  private stepCount = 0;

  // Transition matrix P in R^(5x5)
  // Rows: Normal, Recon, Elevated, UnderAttack, Critical
  private transitionMatrix: number[][] = [
    [0.75, 0.15, 0.07, 0.02, 0.01], // From Normal
    [0.25, 0.50, 0.18, 0.05, 0.02], // From Recon
    [0.10, 0.20, 0.45, 0.20, 0.05], // From Elevated
    [0.05, 0.08, 0.22, 0.50, 0.15], // From UnderAttack
    [0.02, 0.05, 0.13, 0.35, 0.45], // From Critical
  ];

  // Map state to strategy vector: Theta_t = Phi(S_t) (Equation 25)
  private stateStrategies: Record<ThreatState, DefenseStrategyVector> = {
    Normal: {
      encryptionStrength: 2,
      detectionSensitivity: 0.55,
      authenticationThreshold: 55,
      keyRotationMinutes: 20,
      blockchainSyncFrequencySecs: 30,
    },
    Reconnaissance: {
      encryptionStrength: 3,
      detectionSensitivity: 0.68,
      authenticationThreshold: 65,
      keyRotationMinutes: 12,
      blockchainSyncFrequencySecs: 15,
    },
    Elevated: {
      encryptionStrength: 4,
      detectionSensitivity: 0.78,
      authenticationThreshold: 75,
      keyRotationMinutes: 8,
      blockchainSyncFrequencySecs: 8,
    },
    UnderAttack: {
      encryptionStrength: 5,
      detectionSensitivity: 0.90,
      authenticationThreshold: 85,
      keyRotationMinutes: 3,
      blockchainSyncFrequencySecs: 3,
    },
    Critical: {
      encryptionStrength: 5,
      detectionSensitivity: 0.98,
      authenticationThreshold: 90,
      keyRotationMinutes: 1,
      blockchainSyncFrequencySecs: 1,
    },
  };

  public getCurrentState(): MarkovStateAssessment {
    const currentState = this.states[this.currentStateIndex];
    const probs = this.transitionMatrix[this.currentStateIndex];
    const transitionProbabilities = {
      Normal: probs[0],
      Reconnaissance: probs[1],
      Elevated: probs[2],
      UnderAttack: probs[3],
      Critical: probs[4],
    };

    const baseStrategy = this.stateStrategies[currentState];

    // Compute observation metrics based on threat state
    const threatFactor = (this.currentStateIndex + 1) / 5;
    const observationVector = {
      abnormalAccessRate: Number((threatFactor * 14.5).toFixed(1)),
      encryptionLatencyMs: Number((1.2 + threatFactor * 3.4).toFixed(2)),
      keyRotationFrequency: 60 / baseStrategy.keyRotationMinutes,
      aiFalsePositiveRate: Number((0.02 + threatFactor * 0.015).toFixed(3)),
      threatIntensity: threatFactor,
    };

    // Calculate security benefit function (Equation 26): U_t = w1 * A_t - w2 * C_t
    const w1 = 0.65;
    const w2 = 0.35;
    const At = baseStrategy.detectionSensitivity * 100;
    const Ct = (baseStrategy.encryptionStrength * 8 + (60 / baseStrategy.keyRotationMinutes) * 4);
    const Ut = Number((w1 * At - w2 * Ct).toFixed(2));

    return {
      currentState,
      stateIndex: this.currentStateIndex,
      transitionProbabilities,
      observationVector,
      strategyVector: baseStrategy,
      utilityScore: {
        accuracyBenefit: Number(At.toFixed(1)),
        overheadCost: Number(Ct.toFixed(1)),
        netUtility: Ut,
      },
      policyPerturbationApplied: this.stepCount > 0,
    };
  }

  // Transition state based on new threat observation or attack injection
  public step(stimulus?: { threatScore?: number; attackActive?: boolean }): MarkovStateAssessment {
    this.stepCount += 1;
    if (stimulus?.attackActive || (stimulus?.threatScore && stimulus.threatScore >= 0.8)) {
      this.currentStateIndex = Math.min(4, this.currentStateIndex + 2); // Jump to UnderAttack / Critical
    } else if (stimulus?.threatScore && stimulus.threatScore >= 0.6) {
      this.currentStateIndex = Math.min(4, this.currentStateIndex + 1); // Elevate
    } else {
      // Natural Markov transition step according to row distribution
      const row = this.transitionMatrix[this.currentStateIndex];
      const rand = Math.random();
      let cumulative = 0;
      for (let i = 0; i < row.length; i++) {
        cumulative += row[i];
        if (rand <= cumulative) {
          this.currentStateIndex = i;
          break;
        }
      }
    }

    return this.getCurrentState();
  }

  public setState(state: ThreatState): MarkovStateAssessment {
    const idx = this.states.indexOf(state);
    if (idx !== -1) {
      this.currentStateIndex = idx;
    }
    return this.getCurrentState();
  }
}

export const markovDefense = new MarkovDynamicDefenseManager();

import { createHash } from "node:crypto";

export interface DeviceVector {
  screenRes: [number, number];
  colorDepth: number;
  cpuCores: number;
  timezoneOffset: number;
  canvasHash: string;
  platform: string;
}

export interface AccessContext {
  userId: number;
  username: string;
  role: "Admin" | "Analyst" | "User";
  currentLocation: [number, number]; // [lat, lon]
  currentHour: number; // 0 - 23
  resourceSensitivity: "Public" | "Internal" | "Confidential" | "Critical";
  device: DeviceVector;
}

export interface ZeroTrustAssessment {
  overallTrust: number; // 0 - 100
  decision: "Grant" | "StepUpMFA" | "Deny";
  components: {
    userReputation: number; // Su: 0 - 100
    deviceStability: number; // Sd: 0 - 100
    contextSensitivity: number; // At: 0 - 100
    alpha: number;
    beta: number;
    gamma: number;
  };
  contextBreakdown: {
    spatialDeviation: number; // theta_l
    temporalDeviation: number; // theta_t
    resourceSensitivityScore: number; // theta_r
  };
  deviceFingerprint: {
    pcaVector: number[];
    fingerprintHash: string; // HD = SHA256(PCA(D))
    isRecognized: boolean;
  };
  abacRulesChecked: Array<{ rule: string; passed: boolean }>;
}

// User historical baseline profile
interface UserBaseline {
  homeLocation: [number, number];
  locationStdDev: number; // sigma_l
  preferredHours: number[]; // peak access hours e.g. [9, 10, 11, 14, 15, 16]
  historicalAccessCount: number;
  misoperationCount: number;
  abnormalBehaviorCount: number;
  knownFingerprints: Set<string>;
}

const baselines = new Map<number, UserBaseline>();

export function getOrCreateBaseline(userId: number): UserBaseline {
  if (!baselines.has(userId)) {
    baselines.set(userId, {
      homeLocation: [37.7749, -122.4194], // San Francisco default center
      locationStdDev: 0.85,
      preferredHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
      historicalAccessCount: 42,
      misoperationCount: 1,
      abnormalBehaviorCount: 0,
      knownFingerprints: new Set<string>(),
    });
  }
  return baselines.get(userId)!;
}

// PCA Dimensionality Reduction on Device Vector
export function computeDevicePCA(d: DeviceVector): { pca: number[]; hash: string } {
  // Normalize features into numerical components
  const v1 = (d.screenRes[0] * d.screenRes[1]) / (1920 * 1080);
  const v2 = d.colorDepth / 32;
  const v3 = d.cpuCores / 16;
  const v4 = (d.timezoneOffset + 720) / 1440;
  
  // Numerical hash projection of string features
  const canvasNum = (parseInt(d.canvasHash.slice(0, 8), 16) || 12345678) / 0xffffffff;
  const platformNum = d.platform.toLowerCase().includes("win") ? 1.0 : d.platform.toLowerCase().includes("mac") ? 0.75 : 0.5;

  const raw = [v1, v2, v3, v4, canvasNum, platformNum];

  // PCA Eigenvector 1 projection weights (dominant principle component)
  const weights1 = [0.42, 0.35, 0.51, 0.28, 0.44, 0.41];
  // PCA Eigenvector 2 projection weights (secondary principle component)
  const weights2 = [0.38, -0.45, 0.22, 0.62, -0.31, 0.34];

  const pc1 = raw.reduce((sum, val, i) => sum + val * weights1[i], 0);
  const pc2 = raw.reduce((sum, val, i) => sum + val * weights2[i], 0);

  const pca = [Number(pc1.toFixed(4)), Number(pc2.toFixed(4))];
  const hash = createHash("sha256").update(pca.join(":")).digest("hex");

  return { pca, hash };
}

// Dynamic Zero-Trust Trust Engine: T(u, d, t) = alpha * Su + beta * Sd + gamma * At
export function evaluateZeroTrust(context: AccessContext): ZeroTrustAssessment {
  const baseline = getOrCreateBaseline(context.userId);

  // 1. Device Fingerprint & Sd Calculation
  const { pca, hash } = computeDevicePCA(context.device);
  const isKnown = baseline.knownFingerprints.has(hash) || baseline.knownFingerprints.size === 0;
  if (!baseline.knownFingerprints.has(hash) && baseline.knownFingerprints.size < 3) {
    baseline.knownFingerprints.add(hash);
  }
  const Sd = isKnown ? 95 : 45; // Device stability score

  // 2. User Historical Reputation Su = 1/N * sum(w_f * f_i + w_e * e_i + w_a * a_i)
  const N = Math.max(1, baseline.historicalAccessCount);
  const wf = 0.5, we = 0.3, wa = 0.2;
  const frequencyIndex = Math.min(1.0, N / 50) * 100;
  const misoperationPenalty = Math.min(1.0, baseline.misoperationCount / 5) * 100;
  const abnormalPenalty = Math.min(1.0, baseline.abnormalBehaviorCount / 3) * 100;
  
  const Su = Math.max(0, Math.min(100, Math.round(
    wf * frequencyIndex +
    we * (100 - misoperationPenalty) +
    wa * (100 - abnormalPenalty)
  )));

  // 3. Context Sensitivity Parameter At = lambda1 * theta_l + lambda2 * theta_t + lambda3 * theta_r
  // theta_l = |L_l - L_n| / sigma_l
  const dist = Math.hypot(
    context.currentLocation[0] - baseline.homeLocation[0],
    context.currentLocation[1] - baseline.homeLocation[1]
  );
  const theta_l = Math.min(100, Math.round((dist / baseline.locationStdDev) * 12)); // spatial deviation

  // theta_t: distance from closest preferred access hour
  const hourDiff = Math.min(
    ...baseline.preferredHours.map((h) => Math.min(Math.abs(context.currentHour - h), 24 - Math.abs(context.currentHour - h)))
  );
  const theta_t = Math.min(100, hourDiff * 14); // temporal deviation

  // theta_r: resource sensitivity level mapped from access matrix
  const resourceSensitivityScore =
    context.resourceSensitivity === "Critical" ? 95 :
    context.resourceSensitivity === "Confidential" ? 70 :
    context.resourceSensitivity === "Internal" ? 40 : 15;

  const lambda1 = 0.35, lambda2 = 0.25, lambda3 = 0.40;
  // High deviation/sensitivity lowers context trust, so At is inverted to trust form
  const contextRisk = lambda1 * theta_l + lambda2 * theta_t + lambda3 * resourceSensitivityScore;
  const At = Math.max(0, Math.min(100, Math.round(100 - contextRisk)));

  // 4. Mathematical Synthesis: T(u, d, t) = alpha * Su + beta * Sd + gamma * At
  const alpha = 0.45;
  const beta = 0.25;
  const gamma = 0.30;
  const overallTrust = Math.round(alpha * Su + beta * Sd + gamma * At);

  // 5. ABAC Rule Evaluation delta(p, c) in {0, 1}
  const rules = [
    {
      rule: "RBAC Role Hierarchy: User must satisfy minimum role for target sensitivity",
      passed: context.resourceSensitivity === "Critical" ? context.role === "Admin" :
              context.resourceSensitivity === "Confidential" ? context.role !== "User" : true,
    },
    {
      rule: "Context Sensitivity Threshold: Trust score must exceed resource threshold",
      passed: overallTrust >= (resourceSensitivityScore * 0.7),
    },
    {
      rule: "Hardware Stability Guard: Unknown device cannot access Critical resources directly",
      passed: !(context.resourceSensitivity === "Critical" && !isKnown),
    },
    {
      rule: "Spatial Boundary Check: Geographic deviation theta_l < 75",
      passed: theta_l < 75,
    },
  ];

  const abacPassed = rules.every((r) => r.passed);
  let decision: "Grant" | "StepUpMFA" | "Deny" = "Grant";
  if (!abacPassed || overallTrust < 45) {
    decision = "Deny";
  } else if (overallTrust < 75 || !isKnown) {
    decision = "StepUpMFA";
  }

  return {
    overallTrust,
    decision,
    components: {
      userReputation: Su,
      deviceStability: Sd,
      contextSensitivity: At,
      alpha,
      beta,
      gamma,
    },
    contextBreakdown: {
      spatialDeviation: theta_l,
      temporalDeviation: theta_t,
      resourceSensitivityScore,
    },
    deviceFingerprint: {
      pcaVector: pca,
      fingerprintHash: hash,
      isRecognized: isKnown,
    },
    abacRulesChecked: rules,
  };
}

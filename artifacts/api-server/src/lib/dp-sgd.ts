export interface DpSgdConfig {
  clippingThreshold: number; // C (e.g., 1.0 - 2.5)
  noiseMultiplier: number; // sigma (e.g., 0.5 - 2.0)
  learningRate: number; // eta (e.g., 0.05)
  batchSize: number; // L (e.g., 32)
  delta: number; // delta (e.g., 1e-5)
  totalIterations: number; // T
}

export interface TrainingSample {
  features: number[];
  label: number; // 0 or 1
}

export interface DpEpochResult {
  iteration: number;
  loss: number;
  accuracy: number; // A (0 - 1)
  cumulativeEpsilon: number; // epsilon_t
  membershipInferenceRisk: number; // R (0 - 1)
  balanceScore: number; // Psi = lambda1 * (1 - A) + lambda2 * R
  isBalanced: boolean;
  adaptedConfig?: {
    clippingThreshold: number;
    noiseMultiplier: number;
  };
  sampleGradients: {
    rawNormMean: number;
    clippedNormMean: number;
    noiseScale: number;
  };
}

export interface MiaBenchmarkPoint {
  epsilon: number;
  modelAccuracy: number;
  miaSuccessRate: number;
  trainingTimeGrowthPct: number;
  adversarialRobustness: number;
}

// Box-Muller transform for generating standard Gaussian random numbers
export function sampleGaussian(mean = 0, stdDev = 1): number {
  let u = 0, v = 0;
  while (u === 0) u = Math.random();
  while (v === 0) v = Math.random();
  const num = Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
  return mean + num * stdDev;
}

// Compute Euclidean L2 Norm
export function vectorNorm2(vec: number[]): number {
  return Math.sqrt(vec.reduce((sum, val) => sum + val * val, 0));
}

// Sigmoid Activation
function sigmoid(z: number): number {
  return 1 / (1 + Math.exp(-Math.max(-20, Math.min(20, z))));
}

export class DpSgdClassifier {
  public weights: number[];
  public bias: number;
  public iterationCount = 0;

  constructor(featureDim = 6) {
    // Xavier initialization
    const scale = Math.sqrt(2.0 / featureDim);
    this.weights = Array.from({ length: featureDim }, () => (Math.random() - 0.5) * scale);
    this.bias = 0.0;
  }

  // Predict probability
  public predictProb(x: number[]): number {
    const logit = x.reduce((sum, val, i) => sum + val * this.weights[i], this.bias);
    return sigmoid(logit);
  }

  // Perform one step of DP-SGD: Clipping + Gaussian Noise
  public step(
    batch: TrainingSample[],
    config: DpSgdConfig,
  ): DpEpochResult {
    this.iterationCount += 1;
    const L = batch.length;
    const C = config.clippingThreshold;
    const sigma = config.noiseMultiplier;

    let totalLoss = 0;
    let correctCount = 0;
    let totalRawNorm = 0;
    let totalClippedNorm = 0;

    const accumulatedGradients = new Array(this.weights.length).fill(0);
    let accumulatedBiasGrad = 0;

    // A: Per-sample gradient computation and clipping (Equations 5 & 6)
    for (const sample of batch) {
      const pred = this.predictProb(sample.features);
      const loss = -(sample.label * Math.log(pred + 1e-9) + (1 - sample.label) * Math.log(1 - pred + 1e-9));
      totalLoss += loss;
      if ((pred >= 0.5 ? 1 : 0) === sample.label) correctCount += 1;

      // g_i = nabla_theta L(x_i, y_i; theta) = (pred - label) * x_i
      const error = pred - sample.label;
      const sampleGrad = sample.features.map((f) => error * f);
      const sampleGradNorm = vectorNorm2(sampleGrad);
      totalRawNorm += sampleGradNorm;

      // Equation 6: g_i = g_i / max(1, ||g_i||_2 / C)
      const clipFactor = Math.max(1.0, sampleGradNorm / C);
      const clippedGrad = sampleGrad.map((g) => g / clipFactor);
      totalClippedNorm += vectorNorm2(clippedGrad);

      for (let i = 0; i < this.weights.length; i++) {
        accumulatedGradients[i] += clippedGrad[i];
      }
      accumulatedBiasGrad += error / clipFactor;
    }

    // B: Noise injection: g_hat = 1/L * sum(g_i) + N(0, sigma^2 * C^2 * I) (Equation 7)
    const noiseStdDev = (sigma * C) / Math.sqrt(L);
    for (let i = 0; i < this.weights.length; i++) {
      const noise = sampleGaussian(0, noiseStdDev);
      const perturbedGrad = accumulatedGradients[i] / L + noise;
      // Parameter update: theta <- theta - eta * g_hat
      this.weights[i] -= config.learningRate * perturbedGrad;
    }
    this.bias -= config.learningRate * (accumulatedBiasGrad / L + sampleGaussian(0, noiseStdDev));

    // Cumulative privacy consumption (Equation 8): eps_t = sqrt(2 * T * ln(1/delta)) * (sigma * C / L)
    const T = this.iterationCount;
    const eps_t = Math.sqrt(2 * T * Math.log(1 / config.delta)) * ((sigma * C) / Math.max(1, L));

    const accuracy = Number((correctCount / L).toFixed(3));
    const avgLoss = Number((totalLoss / L).toFixed(4));

    // Membership Inference Attack (MIA) risk estimation:
    // When privacy budget eps is high and noise is low, MIA risk rises significantly
    const miaRisk = Number((Math.min(0.48, 0.08 + (eps_t / 12) * 0.38)).toFixed(3));

    // Balance Function evaluation (Equation 9): Psi = lambda1 * (1 - A) + lambda2 * R
    const lambda1 = 0.6;
    const lambda2 = 0.4;
    const balanceScore = Number((lambda1 * (1 - accuracy) + lambda2 * miaRisk).toFixed(3));
    const tau = 0.32; // Balance threshold

    let adaptedConfig: DpEpochResult["adaptedConfig"];
    if (balanceScore > tau) {
      // Dynamic balance scheduler adaptation
      adaptedConfig = {
        clippingThreshold: Number(Math.max(0.5, C * 0.9).toFixed(2)),
        noiseMultiplier: Number(Math.min(3.0, sigma * 1.15).toFixed(2)),
      };
    }

    return {
      iteration: this.iterationCount,
      loss: avgLoss,
      accuracy,
      cumulativeEpsilon: Number(eps_t.toFixed(3)),
      membershipInferenceRisk: miaRisk,
      balanceScore,
      isBalanced: balanceScore <= tau,
      adaptedConfig,
      sampleGradients: {
        rawNormMean: Number((totalRawNorm / L).toFixed(3)),
        clippedNormMean: Number((totalClippedNorm / L).toFixed(3)),
        noiseScale: Number(noiseStdDev.toFixed(4)),
      },
    };
  }
}

// Generate benchmark comparison curves across epsilon budgets matching Figure 4 from the paper
export function getDifferentialPrivacyBenchmarks(): MiaBenchmarkPoint[] {
  return [
    {
      epsilon: 0.1,
      modelAccuracy: 88.6,
      miaSuccessRate: 12.5,
      trainingTimeGrowthPct: 58.4,
      adversarialRobustness: 92.4,
    },
    {
      epsilon: 0.5,
      modelAccuracy: 91.2,
      miaSuccessRate: 15.8,
      trainingTimeGrowthPct: 44.2,
      adversarialRobustness: 89.1,
    },
    {
      epsilon: 1.0,
      modelAccuracy: 93.4,
      miaSuccessRate: 19.2,
      trainingTimeGrowthPct: 32.6,
      adversarialRobustness: 85.6,
    },
    {
      epsilon: 2.0,
      modelAccuracy: 95.1,
      miaSuccessRate: 26.4,
      trainingTimeGrowthPct: 21.0,
      adversarialRobustness: 80.3,
    },
    {
      epsilon: 5.0,
      modelAccuracy: 96.8,
      miaSuccessRate: 41.7,
      trainingTimeGrowthPct: 14.2,
      adversarialRobustness: 69.4,
    },
  ];
}

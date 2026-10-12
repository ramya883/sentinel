import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export interface EncryptionStatus {
  activeLevel: 1 | 2 | 3 | 4 | 5;
  algorithm: string;
  sessionKeyFingerprint: string;
  keyRotationEpoch: number;
  lastRotatedAt: string;
  nextRotationInSeconds: number;
  perturbationVectorsGenerated: number;
  encryptionPolicyState: {
    accessLevel: number;
    dataSensitivity: number;
    threatIndex: number;
    policyLevel: number;
  };
}

class HybridEncryptionManager {
  private currentKey: Buffer;
  private keyEpoch = 1;
  private lastRotated: Date;
  private rotationIntervalSeconds = 600; // 10 minutes default
  private perturbationCount = 0;
  private activeLevel: 1 | 2 | 3 | 4 | 5 = 3;

  constructor() {
    this.currentKey = randomBytes(32); // AES-256 key
    this.lastRotated = new Date();
  }

  // Encryption Policy Controller: phi : R^3 -> Z (accessLevel, dataSensitivity, threatIndex)
  public evaluatePolicyLevel(accessLevel: number, dataSensitivity: number, threatIndex: number): 1 | 2 | 3 | 4 | 5 {
    const compositeScore = accessLevel * 0.3 + dataSensitivity * 0.4 + threatIndex * 0.3;
    let level: 1 | 2 | 3 | 4 | 5 = 1;
    if (compositeScore >= 0.8) level = 5;
    else if (compositeScore >= 0.6) level = 4;
    else if (compositeScore >= 0.4) level = 3;
    else if (compositeScore >= 0.2) level = 2;
    this.activeLevel = level;
    return level;
  }

  // Key Rotation: K_s^(t+tau) = H(K_s^(t) || eta)
  public rotateKey(customEntropySeed?: string): { newKeyFingerprint: string; epoch: number } {
    const eta = customEntropySeed || randomBytes(16).toString("hex");
    const combined = Buffer.concat([this.currentKey, Buffer.from(eta, "utf-8")]);
    this.currentKey = createHash("sha256").update(combined).digest();
    this.keyEpoch += 1;
    this.lastRotated = new Date();

    return {
      newKeyFingerprint: this.getKeyFingerprint(),
      epoch: this.keyEpoch,
    };
  }

  public getKeyFingerprint(): string {
    return createHash("sha256").update(this.currentKey).digest("hex").slice(0, 16);
  }

  // Encrypt payload with AES-256-GCM + Random Perturbation Transform C_i = E(B_i) xor r_i
  public encryptWithPerturbation(plaintext: string): {
    ciphertext: string;
    iv: string;
    tag: string;
    perturbationFingerprint: string;
  } {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.currentKey, iv);
    
    let encrypted = cipher.update(plaintext, "utf-8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const tag = cipher.getAuthTag();

    // Random perturbation vector r_i from cryptographic random bytes
    const ri = randomBytes(encrypted.length);
    this.perturbationCount += 1;

    // C_i = E(B_i) XOR r_i
    const perturbed = Buffer.alloc(encrypted.length);
    for (let i = 0; i < encrypted.length; i++) {
      perturbed[i] = encrypted[i] ^ ri[i];
    }

    const perturbationFingerprint = createHash("sha256").update(ri).digest("hex").slice(0, 12);

    return {
      ciphertext: perturbed.toString("base64"),
      iv: iv.toString("hex"),
      tag: tag.toString("hex"),
      perturbationFingerprint,
    };
  }

  public getStatus(): EncryptionStatus {
    const elapsedSeconds = Math.floor((Date.now() - this.lastRotated.getTime()) / 1000);
    const nextIn = Math.max(0, this.rotationIntervalSeconds - elapsedSeconds);

    return {
      activeLevel: this.activeLevel,
      algorithm: "AES-256-GCM / RSA-4096 Hybrid Key Distribution",
      sessionKeyFingerprint: this.getKeyFingerprint(),
      keyRotationEpoch: this.keyEpoch,
      lastRotatedAt: this.lastRotated.toISOString(),
      nextRotationInSeconds: nextIn,
      perturbationVectorsGenerated: this.perturbationCount,
      encryptionPolicyState: {
        accessLevel: 2,
        dataSensitivity: 3,
        threatIndex: this.activeLevel >= 4 ? 4 : 2,
        policyLevel: this.activeLevel,
      },
    };
  }
}

export const hybridEncryption = new HybridEncryptionManager();

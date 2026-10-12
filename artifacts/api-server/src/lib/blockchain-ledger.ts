import { createHash, randomBytes } from "node:crypto";

export interface Transaction {
  id: string;
  uid: number; // User identity
  op: string; // Operation: access, training, download, invoke_model, alert
  obj: string; // Resource or model object identifier
  ts: string; // ISO Timestamp
  sig: string; // Digital signature: Sign_sk(uid || op || obj || ts)
  hash: string; // hi = SHA256(mi)
}

export interface MerkleProofStep {
  hash: string;
  position: "left" | "right";
}

export interface MerkleProof {
  transactionId: string;
  leafHash: string;
  merkleRoot: string;
  proofPath: MerkleProofStep[];
  pathLength: number; // O(log n)
  isValid: boolean;
}

export interface Block {
  blockNumber: number;
  previousHash: string; // h_{k-1}
  timestamp: string; // T_k
  transactions: Transaction[]; // M_k
  merkleRoot: string; // h_root = Merkle(m1, ..., mn)
  nodeSignatureTime: string; // t_k
  blockHash: string; // h_k = SHA256(h_{k-1} || T_k || M_k)
  validatorNode: string;
}

export class MerkleTree {
  public leaves: string[];
  public levels: string[][];

  constructor(transactionHashes: string[]) {
    this.leaves = transactionHashes.length > 0 ? transactionHashes : [this.hashString("GENESIS_LEAF")];
    this.levels = [this.leaves];
    this.buildTree();
  }

  private hashString(val: string): string {
    return createHash("sha256").update(val).digest("hex");
  }

  private combineHashes(left: string, right: string): string {
    return this.hashString(`${left}|${right}`);
  }

  private buildTree(): void {
    let currentLevel = this.leaves;
    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left; // Duplicate last if odd
        nextLevel.push(this.combineHashes(left, right));
      }
      this.levels.push(nextLevel);
      currentLevel = nextLevel;
    }
  }

  public getRoot(): string {
    return this.levels[this.levels.length - 1][0];
  }

  public getProof(leafHash: string): MerkleProofStep[] {
    const proof: MerkleProofStep[] = [];
    let index = this.leaves.indexOf(leafHash);
    if (index === -1) return proof;

    for (let levelIndex = 0; levelIndex < this.levels.length - 1; levelIndex++) {
      const level = this.levels[levelIndex];
      const isRightChild = index % 2 === 1;
      const siblingIndex = isRightChild ? index - 1 : index + 1;

      if (siblingIndex < level.length) {
        proof.push({
          hash: level[siblingIndex],
          position: isRightChild ? "left" : "right",
        });
      } else {
        // Paired with self
        proof.push({
          hash: level[index],
          position: "right",
        });
      }
      index = Math.floor(index / 2);
    }
    return proof;
  }

  public static verifyProof(leafHash: string, proof: MerkleProofStep[], root: string): boolean {
    let current = leafHash;
    for (const step of proof) {
      if (step.position === "left") {
        current = createHash("sha256").update(`${step.hash}|${current}`).digest("hex");
      } else {
        current = createHash("sha256").update(`${current}|${step.hash}`).digest("hex");
      }
    }
    return current === root;
  }
}

class BlockchainLedger {
  private chain: Block[] = [];
  private mempool: Transaction[] = [];

  constructor() {
    this.createGenesisBlock();
  }

  private createGenesisBlock(): void {
    const genesisTx: Transaction = {
      id: "TX-GENESIS-0000",
      uid: 0,
      op: "SYSTEM_INITIALIZE",
      obj: "SENTINEL_ROOT",
      ts: new Date(Date.now() - 3600 * 24 * 1000).toISOString(),
      sig: "0000000000000000000000000000000000000000000000000000000000000000",
      hash: createHash("sha256").update("GENESIS_INIT").digest("hex"),
    };

    const tree = new MerkleTree([genesisTx.hash]);
    const prevHash = "0000000000000000000000000000000000000000000000000000000000000000";
    const ts = new Date(Date.now() - 3600 * 24 * 1000).toISOString();
    const blockHash = createHash("sha256").update(`${prevHash}||${ts}||${tree.getRoot()}`).digest("hex");

    this.chain.push({
      blockNumber: 0,
      previousHash: prevHash,
      timestamp: ts,
      transactions: [genesisTx],
      merkleRoot: tree.getRoot(),
      nodeSignatureTime: ts,
      blockHash,
      validatorNode: "Orderer-Peer-0 (Raft Leader)",
    });
  }

  // Create standardized transaction mi = <uid, op, obj, ts, sig>
  public addTransaction(input: { uid: number; op: string; obj: string }): Transaction {
    const ts = new Date().toISOString();
    const payload = `${input.uid}||${input.op}||${input.obj}||${ts}`;
    const sig = createHash("sha256").update(`PRIVKEY_${payload}`).digest("hex");
    const hash = createHash("sha256").update(payload + sig).digest("hex");

    const tx: Transaction = {
      id: `TX-${randomBytes(4).toString("hex").toUpperCase()}`,
      uid: input.uid,
      op: input.op,
      obj: input.obj,
      ts,
      sig,
      hash,
    };

    this.mempool.push(tx);

    // Auto-mine block if mempool reaches batch threshold
    if (this.mempool.length >= 3) {
      this.mineBlock();
    }

    return tx;
  }

  // Smart Contract: InvokeModel(userId, modelId, version, timestamp)
  public invokeModel(userId: number, modelId: string, version: string): Transaction {
    return this.addTransaction({
      uid: userId,
      op: "InvokeModel",
      obj: `Model:${modelId}@v${version}`,
    });
  }

  public mineBlock(): Block | null {
    if (this.mempool.length === 0) return null;

    const txs = [...this.mempool];
    this.mempool = [];

    const prevBlock = this.chain[this.chain.length - 1];
    const tree = new MerkleTree(txs.map((t) => t.hash));
    const ts = new Date().toISOString();
    const sigTime = new Date().toISOString();

    // Equation (20): h_k = SHA256(h_{k-1} || T_k || M_k)
    const blockHash = createHash("sha256")
      .update(`${prevBlock.blockHash}||${ts}||${tree.getRoot()}`)
      .digest("hex");

    const block: Block = {
      blockNumber: this.chain.length,
      previousHash: prevBlock.blockHash,
      timestamp: ts,
      transactions: txs,
      merkleRoot: tree.getRoot(),
      nodeSignatureTime: sigTime,
      blockHash,
      validatorNode: `Orderer-Peer-${(this.chain.length % 3)} (PBFT Quorum)`,
    };

    this.chain.push(block);
    return block;
  }

  public getBlocks(): Block[] {
    return this.chain;
  }

  public getProofForTransaction(txId: string): MerkleProof | null {
    for (const block of this.chain) {
      const tx = block.transactions.find((t) => t.id === txId);
      if (tx) {
        const tree = new MerkleTree(block.transactions.map((t) => t.hash));
        const proofPath = tree.getProof(tx.hash);
        const isValid = MerkleTree.verifyProof(tx.hash, proofPath, block.merkleRoot);

        return {
          transactionId: tx.id,
          leafHash: tx.hash,
          merkleRoot: block.merkleRoot,
          proofPath,
          pathLength: proofPath.length,
          isValid,
        };
      }
    }
    return null;
  }
}

export const blockchainLedger = new BlockchainLedger();

// Pre-seed a few demo transactions & blocks for verification
blockchainLedger.addTransaction({ uid: 1, op: "AccessGranted", obj: "Dashboard:Overview" });
blockchainLedger.addTransaction({ uid: 1, op: "InvokeModel", obj: "Model:GRU-Autoencoder@v2.1" });
blockchainLedger.addTransaction({ uid: 1, op: "PolicyReconfigured", obj: "Encryption:Level-4" });
blockchainLedger.mineBlock();
blockchainLedger.addTransaction({ uid: 1, op: "IntrusionMitigated", obj: "IPS-RULE-0001:Hardware-Isolation" });
blockchainLedger.mineBlock();

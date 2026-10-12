export type TrafficVector = [
  number,
  number,
  number,
  number,
  number,
  number,
];

type Tree =
  | { leaf: true; size: number }
  | { leaf: false; feature: number; split: number; left: Tree; right: Tree };

const FEATURE_COUNT = 6;
const TREE_COUNT = 32;

function harmonic(n: number): number {
  if (n <= 1) return 0;
  return Math.log(n) + 0.5772156649 + 1 / (2 * n);
}

function averagePathLength(n: number): number {
  if (n <= 1) return 0;
  return 2 * harmonic(n - 1) - (2 * (n - 1)) / n;
}

function buildTree(
  data: TrafficVector[],
  depth: number,
  maxDepth: number,
  nextRandom: () => number,
): Tree {
  if (data.length <= 1 || depth >= maxDepth) return { leaf: true, size: data.length };
  const feature = Math.floor(nextRandom() * FEATURE_COUNT);
  const values = data.map((row) => row[feature]);
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (min === max) return { leaf: true, size: data.length };
  const split = min + nextRandom() * (max - min);
  const left = data.filter((row) => row[feature] < split);
  const right = data.filter((row) => row[feature] >= split);
  if (!left.length || !right.length) return { leaf: true, size: data.length };
  return {
    leaf: false,
    feature,
    split,
    left: buildTree(left, depth + 1, maxDepth, nextRandom),
    right: buildTree(right, depth + 1, maxDepth, nextRandom),
  };
}

function pathLength(row: TrafficVector, tree: Tree, depth = 0): number {
  if (tree.leaf) return depth + averagePathLength(tree.size);
  return pathLength(
    row,
    row[tree.feature] < tree.split ? tree.left : tree.right,
    depth + 1,
  );
}

export function isolationForestScore(row: TrafficVector, data: TrafficVector[]): number {
  if (data.length < 4) return 0.5;
  const maxDepth = Math.ceil(Math.log2(data.length));
  let seed = 1337;
  const nextRandom = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 4294967296;
  };
  const paths = Array.from({ length: TREE_COUNT }, () => {
    const sample = [...data].sort(() => nextRandom() - 0.5).slice(0, Math.min(64, data.length));
    return pathLength(row, buildTree(sample, 0, maxDepth, nextRandom));
  });
  const averagePath = paths.reduce((sum, value) => sum + value, 0) / paths.length;
  const normalizer = averagePathLength(Math.min(64, data.length)) || 1;
  return Math.max(0, Math.min(1, Math.pow(2, -averagePath / normalizer)));
}

export function riskForAnomaly(score: number): "Low" | "Medium" | "High" {
  if (score >= 0.78) return "High";
  if (score >= 0.62) return "Medium";
  return "Low";
}
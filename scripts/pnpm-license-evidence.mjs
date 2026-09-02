function packageNames(report) {
  return Object.values(report)
    .flat()
    .map((entry) => entry.name)
    .sort();
}

export function assertPnpmLicenseEvidenceMatches(candidate, fresh) {
  const candidateNames = packageNames(candidate);
  const freshNames = packageNames(fresh);
  if (JSON.stringify(candidateNames) !== JSON.stringify(freshNames)) {
    throw new Error("pnpm license evidence package names do not match");
  }
}

export function normalizePnpmLicenseEvidence(report) {
  if (report === null || typeof report !== "object" || Array.isArray(report)) {
    throw new Error("pnpm license evidence must be an object grouped by license");
  }

  const records = [];
  for (const [licenseGroup, entries] of Object.entries(report)) {
    if (!Array.isArray(entries)) {
      throw new Error(`pnpm license group ${licenseGroup} must be an array`);
    }
    for (const entry of entries) {
      if (
        entry === null
        || typeof entry !== "object"
        || typeof entry.name !== "string"
        || entry.name.length === 0
        || typeof entry.license !== "string"
        || entry.license.length === 0
        || !Array.isArray(entry.versions)
        || entry.versions.length === 0
        || entry.versions.some((version) => typeof version !== "string" || version.length === 0)
      ) {
        throw new Error(`invalid pnpm license entry in ${licenseGroup}`);
      }
      for (const version of entry.versions) {
        records.push({ name: entry.name, version, license: entry.license });
      }
    }
  }
  records.sort((left, right) => (
    left.name.localeCompare(right.name)
    || left.version.localeCompare(right.version)
    || left.license.localeCompare(right.license)
  ));
  for (let index = 1; index < records.length; index += 1) {
    if (JSON.stringify(records[index]) === JSON.stringify(records[index - 1])) {
      throw new Error(`duplicate pnpm license record: ${JSON.stringify(records[index])}`);
    }
  }
  return records;
}

export function assertPnpmLicenseEvidenceMatches(candidate, fresh) {
  const candidateRecords = normalizePnpmLicenseEvidence(candidate);
  const freshRecords = normalizePnpmLicenseEvidence(fresh);
  if (JSON.stringify(candidateRecords) !== JSON.stringify(freshRecords)) {
    throw new Error("pnpm license evidence name, version, and license inventory does not match");
  }
}

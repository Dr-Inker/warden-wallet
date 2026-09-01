import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, relative } from "node:path";

export const PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA =
  "warden.extension-production-dependency-evidence.v1";

const SCOPE = Object.freeze({
  type: "pnpm-installed-production-closure",
  bundleCoverage: "not-asserted",
  licenseMeaning: "package-declared-metadata-not-legal-conclusion",
});

function fail(message) {
  throw new Error(`extension production dependency evidence: ${message}`);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertExactKeys(value, expected, label) {
  if (!isPlainObject(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} keys changed: expected ${wanted.join(",")}, got ${actual.join(",")}`);
  }
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertHash(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${label} must be a lowercase SHA-256 digest`);
  }
}

function assertPackageName(value, label) {
  if (
    typeof value !== "string" ||
    !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(value)
  ) {
    fail(`${label} must be a canonical npm package name`);
  }
}

function assertVersion(value, label) {
  if (
    typeof value !== "string" ||
    !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value)
  ) {
    fail(`${label} must be an exact semantic version`);
  }
}

function assertSource(source) {
  assertExactKeys(source, ["gitCommit", "lockfileSha256"], "evidence source");
  if (typeof source.gitCommit !== "string" || !/^[0-9a-f]{40}$/.test(source.gitCommit)) {
    fail("evidence source gitCommit must be a full lowercase commit SHA");
  }
  assertHash(source.lockfileSha256, "evidence source lockfileSha256");
}

function componentId(kind, name, version) {
  return `${kind === "registry" ? "npm" : "workspace"}:${name}@${version}`;
}

async function readPackageJson(packageDirectory) {
  const packagePath = join(packageDirectory, "package.json");
  let packageJson;
  try {
    packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  } catch (error) {
    fail(`installed package.json is unreadable at ${packagePath}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!isPlainObject(packageJson)) {
    fail(`installed package.json root must be an object at ${packagePath}`);
  }
  return packageJson;
}

function isWithin(parent, candidate) {
  const path = relative(parent, candidate);
  return path === "" || (!path.startsWith("..") && !isAbsolute(path));
}

async function resolveInstalledDependency(fromDirectory, name, repositoryRoot) {
  const packageSegments = name.split("/");
  let cursor = fromDirectory;
  while (true) {
    const candidate = join(cursor, "node_modules", ...packageSegments);
    try {
      const candidateStat = await lstat(candidate);
      if (!candidateStat.isDirectory() && !candidateStat.isSymbolicLink()) {
        fail(`installed dependency path is not a directory or symlink: ${name}`);
      }
      const resolved = await realpath(candidate);
      if (!isWithin(repositoryRoot, resolved)) {
        fail(`installed dependency escapes the repository: ${name}`);
      }
      return resolved;
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
    }
    const parent = dirname(cursor);
    if (parent === cursor) {
      return undefined;
    }
    cursor = parent;
  }
}

function productionDependencyDeclarations(packageJson, packageName) {
  const dependencies = packageJson.dependencies ?? {};
  const optionalDependencies = packageJson.optionalDependencies ?? {};
  const peerDependencies = packageJson.peerDependencies ?? {};
  const peerDependenciesMeta = packageJson.peerDependenciesMeta ?? {};
  if (
    !isPlainObject(dependencies) ||
    !isPlainObject(optionalDependencies) ||
    !isPlainObject(peerDependencies) ||
    !isPlainObject(peerDependenciesMeta)
  ) {
    fail(`production dependency declarations are invalid for ${packageName}`);
  }
  const declarations = new Map();
  for (const name of Object.keys(dependencies)) {
    assertPackageName(name, `dependency name declared by ${packageName}`);
    declarations.set(name, { optional: false });
  }
  for (const name of Object.keys(optionalDependencies)) {
    assertPackageName(name, `optional dependency name declared by ${packageName}`);
    if (!declarations.has(name)) {
      declarations.set(name, { optional: true });
    }
  }
  for (const name of Object.keys(peerDependencies)) {
    assertPackageName(name, `peer dependency name declared by ${packageName}`);
    if (!declarations.has(name)) {
      const metadata = peerDependenciesMeta[name];
      if (metadata !== undefined && !isPlainObject(metadata)) {
        fail(`peer dependency metadata is invalid for ${packageName} -> ${name}`);
      }
      declarations.set(name, { optional: metadata?.optional === true });
    }
  }
  return [...declarations.entries()].sort(([left], [right]) => compareUtf8(left, right));
}

export async function collectInstalledProductionDependencyReports({
  rootDirectory,
  repositoryRoot,
}) {
  const canonicalRepositoryRoot = await realpath(repositoryRoot);
  const canonicalRootDirectory = await realpath(rootDirectory);
  if (!isWithin(canonicalRepositoryRoot, canonicalRootDirectory)) {
    fail("production dependency root must be inside the repository");
  }
  const registryRoot = join(canonicalRepositoryRoot, "node_modules");
  const workspaces = new Map();
  const visitedPackageRoots = new Set();
  const licenseVersions = new Map();

  async function inspectPackage(packageDirectory, expectedName) {
    const packageJson = await readPackageJson(packageDirectory);
    assertPackageName(packageJson.name, `installed package name at ${packageDirectory}`);
    assertVersion(packageJson.version, `installed package version for ${packageJson.name}`);
    if (expectedName !== undefined && packageJson.name !== expectedName) {
      fail(`installed package identity disagrees: expected ${expectedName}, got ${packageJson.name}`);
    }
    const workspace = !isWithin(registryRoot, packageDirectory);
    const node = workspace
      ? { from: packageJson.name, version: `link:${packageJson.name}`, dependencies: {} }
      : {
        from: packageJson.name,
        version: packageJson.version,
        resolved: "https://registry.npmjs.org/",
        dependencies: {},
      };
    if (workspace && !workspaces.has(packageJson.name)) {
      workspaces.set(packageJson.name, {
        name: packageJson.name,
        version: packageJson.version,
        dependencies: node.dependencies,
      });
    }
    if (!workspace) {
      const declaredLicense =
        typeof packageJson.license === "string" && packageJson.license.length > 0
          ? packageJson.license
          : "Unknown";
      const licenseKey = `${declaredLicense}\0${packageJson.name}`;
      const versions = licenseVersions.get(licenseKey) ?? new Set();
      versions.add(packageJson.version);
      licenseVersions.set(licenseKey, versions);
    }

    if (visitedPackageRoots.has(packageDirectory)) {
      delete node.dependencies;
      return node;
    }
    visitedPackageRoots.add(packageDirectory);
    for (const [dependencyName, declaration] of productionDependencyDeclarations(
      packageJson,
      packageJson.name,
    )) {
      const dependencyRoot = await resolveInstalledDependency(
        packageDirectory,
        dependencyName,
        canonicalRepositoryRoot,
      );
      if (dependencyRoot === undefined) {
        if (declaration.optional) {
          continue;
        }
        fail(`required production dependency is not installed: ${packageJson.name} -> ${dependencyName}`);
      }
      node.dependencies[dependencyName] = await inspectPackage(dependencyRoot, dependencyName);
    }
    return node;
  }

  const rootPackage = await readPackageJson(canonicalRootDirectory);
  const rootNode = await inspectPackage(canonicalRootDirectory, rootPackage.name);
  const rootWorkspace = workspaces.get(rootPackage.name);
  rootWorkspace.dependencies = rootNode.dependencies;

  const licenseReport = {};
  for (const key of [...licenseVersions.keys()].sort(compareUtf8)) {
    const [license, name] = key.split("\0");
    const records = licenseReport[license] ?? [];
    records.push({
      name,
      versions: [...licenseVersions.get(key)].sort(compareUtf8),
      license,
    });
    licenseReport[license] = records;
  }
  return {
    dependencyReport: [...workspaces.values()].sort((left, right) => compareUtf8(left.name, right.name)),
    licenseReport,
  };
}

function collectDeclaredLicenses(licenseReport) {
  if (!isPlainObject(licenseReport)) {
    fail("pnpm license report must be an object");
  }
  const licenses = new Map();
  for (const [group, records] of Object.entries(licenseReport)) {
    if (typeof group !== "string" || group.length === 0 || !Array.isArray(records)) {
      fail("pnpm license report group is invalid");
    }
    for (const record of records) {
      if (!isPlainObject(record)) {
        fail(`pnpm license report entry in ${group} must be an object`);
      }
      assertPackageName(record.name, `pnpm license report package in ${group}`);
      if (record.license !== group || typeof record.license !== "string" || record.license.length === 0) {
        fail(`pnpm license report group disagrees with ${record.name}`);
      }
      if (!Array.isArray(record.versions) || record.versions.length === 0) {
        fail(`pnpm license report versions are missing for ${record.name}`);
      }
      for (const version of record.versions) {
        assertVersion(version, `pnpm license report version for ${record.name}`);
        const id = componentId("registry", record.name, version);
        if (licenses.has(id)) {
          fail(`duplicate declared-license metadata for ${record.name}@${version}`);
        }
        licenses.set(id, record.license);
      }
    }
  }
  return licenses;
}

function collectComponents(dependencyReport, rootPackage, declaredLicenses) {
  if (!Array.isArray(dependencyReport) || dependencyReport.length === 0) {
    fail("pnpm production dependency report must be a non-empty array");
  }
  assertExactKeys(rootPackage, ["name", "version"], "root package");
  assertPackageName(rootPackage.name, "root package name");
  assertVersion(rootPackage.version, "root package version");

  const workspaces = new Map();
  for (const workspace of dependencyReport) {
    if (!isPlainObject(workspace)) {
      fail("pnpm production dependency workspace must be an object");
    }
    assertPackageName(workspace.name, "pnpm workspace name");
    assertVersion(workspace.version, `pnpm workspace version for ${workspace.name}`);
    if (workspaces.has(workspace.name)) {
      fail(`duplicate pnpm workspace entry for ${workspace.name}`);
    }
    workspaces.set(workspace.name, workspace);
  }
  const rootWorkspace = workspaces.get(rootPackage.name);
  if (rootWorkspace === undefined || rootWorkspace.version !== rootPackage.version) {
    fail(`pnpm production dependency report does not contain ${rootPackage.name}@${rootPackage.version}`);
  }

  const components = new Map();

  function ensureComponent(kind, name, version) {
    const id = componentId(kind, name, version);
    const existing = components.get(id);
    if (existing !== undefined) {
      return existing;
    }
    const component = {
      id,
      kind,
      name,
      version,
      declaredLicense: kind === "registry" ? declaredLicenses.get(id) : null,
      dependencies: new Set(),
    };
    if (kind === "registry" && component.declaredLicense === undefined) {
      fail(`missing declared-license metadata for ${name}@${version}`);
    }
    components.set(id, component);
    return component;
  }

  function visitDependencies(parent, dependencies) {
    if (dependencies === undefined) {
      return;
    }
    if (!isPlainObject(dependencies)) {
      fail(`pnpm dependencies for ${parent.id} must be an object`);
    }
    for (const [name, node] of Object.entries(dependencies)) {
      assertPackageName(name, `dependency name under ${parent.id}`);
      if (!isPlainObject(node) || typeof node.version !== "string") {
        fail(`dependency record for ${name} under ${parent.id} is invalid`);
      }
      if (node.from !== undefined && node.from !== name) {
        fail(`dependency record name disagrees for ${name} under ${parent.id}`);
      }
      let child;
      if (node.version.startsWith("link:")) {
        const workspace = workspaces.get(name);
        if (workspace === undefined) {
          fail(`linked production dependency is absent from pnpm workspace report: ${name}`);
        }
        child = ensureComponent("workspace", name, workspace.version);
        visitDependencies(child, node.dependencies);
        if (workspace.dependencies !== node.dependencies) {
          visitDependencies(child, workspace.dependencies);
        }
      } else {
        assertVersion(node.version, `dependency version for ${name}`);
        if (
          typeof node.resolved !== "string" ||
          !node.resolved.startsWith("https://registry.npmjs.org/")
        ) {
          fail(`registry dependency ${name}@${node.version} lacks the reviewed npm registry resolution`);
        }
        child = ensureComponent("registry", name, node.version);
        visitDependencies(child, node.dependencies);
      }
      parent.dependencies.add(child.id);
    }
  }

  const root = ensureComponent("workspace", rootPackage.name, rootPackage.version);
  visitDependencies(root, rootWorkspace.dependencies);

  for (const id of declaredLicenses.keys()) {
    if (!components.has(id)) {
      fail(`declared-license metadata is outside the production closure: ${id.slice(4)}`);
    }
  }

  return [...components.values()]
    .map((component) => ({
      ...component,
      dependencies: [...component.dependencies].sort(compareUtf8),
    }))
    .sort((left, right) => compareUtf8(left.id, right.id));
}

function assertEvidenceShape(evidence) {
  assertExactKeys(evidence, ["schema", "scope", "source", "artifact", "components"], "dependency evidence");
  if (evidence.schema !== PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA) {
    fail(`unsupported evidence schema: ${String(evidence.schema)}`);
  }
  assertExactKeys(
    evidence.scope,
    ["type", "rootComponent", "bundleCoverage", "licenseMeaning"],
    "evidence scope",
  );
  if (
    evidence.scope.type !== SCOPE.type ||
    evidence.scope.bundleCoverage !== SCOPE.bundleCoverage ||
    evidence.scope.licenseMeaning !== SCOPE.licenseMeaning ||
    typeof evidence.scope.rootComponent !== "string"
  ) {
    fail("evidence scope is not the reviewed production-closure scope");
  }
  assertSource(evidence.source);
  assertExactKeys(evidence.artifact, ["archiveFile", "archiveSha256"], "evidence artifact");
  if (
    typeof evidence.artifact.archiveFile !== "string" ||
    !/^[A-Za-z0-9._-]+\.zip$/.test(evidence.artifact.archiveFile)
  ) {
    fail("evidence archive file is invalid");
  }
  assertHash(evidence.artifact.archiveSha256, "evidence archive sha256");
  if (!Array.isArray(evidence.components) || evidence.components.length === 0) {
    fail("evidence components must be a non-empty array");
  }
  const componentIds = new Set();
  let previousId;
  for (const component of evidence.components) {
    assertExactKeys(
      component,
      ["id", "kind", "name", "version", "declaredLicense", "dependencies"],
      "evidence component",
    );
    assertPackageName(component.name, "evidence component name");
    assertVersion(component.version, `evidence component version for ${component.name}`);
    if (component.kind !== "workspace" && component.kind !== "registry") {
      fail(`evidence component kind is invalid for ${component.name}`);
    }
    if (component.id !== componentId(component.kind, component.name, component.version)) {
      fail(`evidence component id is inconsistent for ${component.name}`);
    }
    if (previousId !== undefined && compareUtf8(previousId, component.id) >= 0) {
      fail("evidence components are not unique and canonically sorted");
    }
    previousId = component.id;
    componentIds.add(component.id);
    if (
      (component.kind === "workspace" && component.declaredLicense !== null) ||
      (component.kind === "registry" &&
        (typeof component.declaredLicense !== "string" || component.declaredLicense.length === 0))
    ) {
      fail(`evidence declared-license metadata is invalid for ${component.id}`);
    }
    if (!Array.isArray(component.dependencies)) {
      fail(`evidence dependencies must be an array for ${component.id}`);
    }
    let previousDependency;
    for (const dependency of component.dependencies) {
      if (
        typeof dependency !== "string" ||
        (previousDependency !== undefined && compareUtf8(previousDependency, dependency) >= 0)
      ) {
        fail(`evidence dependencies are not unique and canonically sorted for ${component.id}`);
      }
      previousDependency = dependency;
    }
  }
  if (!componentIds.has(evidence.scope.rootComponent)) {
    fail("evidence root component is absent from components");
  }
  for (const component of evidence.components) {
    for (const dependency of component.dependencies) {
      if (!componentIds.has(dependency)) {
        fail(`evidence dependency is absent from components: ${dependency}`);
      }
    }
  }
}

export function createProductionDependencyEvidence({
  dependencyReport,
  licenseReport,
  rootPackage,
  source,
  archiveFileName,
  archiveBytes,
}) {
  if (!(archiveBytes instanceof Uint8Array) || archiveBytes.length === 0) {
    fail("archive must be non-empty byte data");
  }
  const declaredLicenses = collectDeclaredLicenses(licenseReport);
  const components = collectComponents(dependencyReport, rootPackage, declaredLicenses);
  const evidence = {
    schema: PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA,
    scope: {
      type: SCOPE.type,
      rootComponent: componentId("workspace", rootPackage.name, rootPackage.version),
      bundleCoverage: SCOPE.bundleCoverage,
      licenseMeaning: SCOPE.licenseMeaning,
    },
    source: {
      gitCommit: source?.gitCommit,
      lockfileSha256: source?.lockfileSha256,
    },
    artifact: {
      archiveFile: archiveFileName,
      archiveSha256: sha256(archiveBytes),
    },
    components,
  };
  assertEvidenceShape(evidence);
  return evidence;
}

export function serializeProductionDependencyEvidence(evidence) {
  assertEvidenceShape(evidence);
  return `${JSON.stringify(evidence, null, 2)}\n`;
}

export function parseProductionDependencyEvidence(bytes) {
  const evidenceBytes = Buffer.from(bytes);
  const evidenceText = evidenceBytes.toString("utf8");
  if (!Buffer.from(evidenceText, "utf8").equals(evidenceBytes)) {
    fail("evidence is not canonical UTF-8");
  }
  let evidence;
  try {
    evidence = JSON.parse(evidenceText);
  } catch (error) {
    fail(`evidence is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  assertEvidenceShape(evidence);
  if (evidenceText !== serializeProductionDependencyEvidence(evidence)) {
    fail("evidence must use the canonical generated JSON serialization");
  }
  return evidence;
}

export function verifyProductionDependencyEvidenceAttachment({
  evidenceBytes,
  artifactManifest,
  archiveBytes,
}) {
  if (!(evidenceBytes instanceof Uint8Array) || !(archiveBytes instanceof Uint8Array)) {
    fail("evidence and archive must be byte data");
  }
  const attachment = artifactManifest?.dependencyEvidence;
  if (!isPlainObject(attachment)) {
    fail("artifact manifest does not bind dependency evidence");
  }
  if (
    attachment.schema !== PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA ||
    attachment.bytes !== evidenceBytes.length ||
    attachment.sha256 !== sha256(evidenceBytes)
  ) {
    fail("evidence bytes differ from the artifact manifest attachment");
  }
  const evidence = parseProductionDependencyEvidence(evidenceBytes);
  if (
    evidence.source.gitCommit !== artifactManifest.source?.gitCommit ||
    evidence.source.lockfileSha256 !== artifactManifest.source?.lockfileSha256
  ) {
    fail("evidence source differs from the artifact manifest source");
  }
  if (
    archiveBytes.length !== artifactManifest.archive?.bytes ||
    sha256(archiveBytes) !== artifactManifest.archive?.sha256
  ) {
    fail("archive bytes differ from the artifact manifest");
  }
  if (
    evidence.artifact.archiveFile !== artifactManifest.archive.file ||
    evidence.artifact.archiveSha256 !== artifactManifest.archive.sha256
  ) {
    fail("evidence archive binding differs from the artifact manifest");
  }
  if (
    evidence.scope.rootComponent !==
      componentId("workspace", "@warden/extension", artifactManifest.extension?.version)
  ) {
    fail("evidence root component differs from the artifact extension identity");
  }
  return { components: evidence.components.length };
}

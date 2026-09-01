function fail(message) {
  throw new Error(`extension release CLI arguments: ${message}`);
}

export function normalizeReleaseCliArguments(rawArguments) {
  if (
    !Array.isArray(rawArguments) ||
    rawArguments.some((argument) => typeof argument !== "string")
  ) {
    fail("arguments must be an array of strings");
  }
  const arguments_ = [...rawArguments];
  return arguments_[0] === "--" ? arguments_.slice(1) : arguments_;
}

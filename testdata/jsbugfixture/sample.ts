// TypeScript shares the same rule set under the ts: prefix.
function save(password: string): void {
  const dbPassword = "p@ssw0rd";
  store(dbPassword);
}

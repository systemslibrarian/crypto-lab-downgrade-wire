/** Sibling labs this demo links out to instead of rebuilding (scope guard, §1). */
const gh = (repo: string) => `https://systemslibrarian.github.io/${repo}/`;

export const LABS = {
  catalog: 'https://crypto-lab.systemslibrarian.dev/',
  hybridWire: gh('crypto-lab-hybrid-wire'), // the hybrid KEX this lab consumes
  hybridGuide: gh('crypto-lab-hybrid-guide'),
  hybridPqc: gh('crypto-lab-hybrid-pqc'),
  tlsHandshake: gh('crypto-lab-tls-handshake'),
  pqTlsHandshake: gh('crypto-lab-pq-tls-handshake'),
  keyExchange: gh('crypto-lab-key-exchange'),
  harvestTimeline: gh('crypto-lab-harvest-timeline'),
} as const;

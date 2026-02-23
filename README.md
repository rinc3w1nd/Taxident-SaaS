# Taxident

Taxident is a zero-knowledge encrypted SaaS for deterministic multi-jurisdiction tax residency analysis, targeting globally mobile individuals.

The server never sees plaintext user data. Identity is established via WebAuthn credentials with no email or username. Account recovery uses BIP39 mnemonic-based deterministic key derivation. User data is stored as per-record encrypted rows following the Tuta/Proton model, with advisor delegation via wrapped period keys.

## Current Schema Versions

- **Server schema:** v3.1 — `schema/server/v3.1/taxident_server_schema_v3.1.sql`
- **Client schema:** v2.1 — `schema/client/v2.1/taxident_client_schema_v2.1.sql`

## Repository Structure

```
taxident/
├── docs/
│   ├── design/          # Design documents
│   ├── erd/             # Entity-relationship diagrams (Mermaid)
│   └── market/          # Market analysis
├── schema/
│   ├── server/          # Server-side schemas (versioned)
│   │   ├── v3/
│   │   └── v3.1/
│   └── client/          # Client-side schemas (versioned)
│       ├── v2/
│       └── v2.1/
├── src/                 # Application source code
├── .gitignore
└── README.md
```

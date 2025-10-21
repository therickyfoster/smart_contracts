![Header](https://capsule-render.vercel.app/api?type=waving&color=0:83a4d4,100:b6fbff&height=200&section=header&text=Gamified%20Peace%20Protocol&fontSize=64&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=Integrity-Guarded%20Smart%20Contracts%20for%20Peace%20Incentives&descAlignY=55&descSize=20)

<div align="center">

[![Suite](https://img.shields.io/badge/35_Contract_Suite-Integrity_Guarded-2d3748?style=for-the-badge&labelColor=2d3748&color=38a169)](#)
[![Anti-Inversion](https://img.shields.io/badge/Anti–Inversion-Dual_Hash_Provenance-2d3748?style=for-the-badge&labelColor=2d3748&color=805ad5)](#)
[![Upgradability](https://img.shields.io/badge/UUPS-Proxy_Safe-2d3748?style=for-the-badge&labelColor=2d3748&color=3182ce)](#)
[![Zero-Harm](https://img.shields.io/badge/Zero_Harm-Non_Weaponization-2d3748?style=for-the-badge&labelColor=2d3748&color=dd6b20)](#)

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&pause=1000&color=38A169&center=true&vCenter=true&width=720&lines=Peace+as+a+Protocol;+Verified+Impact+→+XP%2C+Reputation%2C+ETH;+Integrity-Guarded+Upgrades;+On-Chain+Leaderboards+%26+Seasons" alt="Typing SVG" />
</p>

🌐 **[Planetary Restoration Archive](https://planetaryrestorationarchive.com)**  
📧 **[admin@planetaryrestorationarchive.com](mailto:admin@planetaryrestorationarchive.com)**

</div>

---

## 🔧 Suite Overview

**Purpose:** Turn verified de-escalation and humanitarian outcomes into on-chain incentives.  
**Stack:** Solidity • UUPS (EIP-1967) • Ethers • Foundry/Hardhat • OpenZeppelin patterns (re-implemented where needed)  
**Guardrails:** Anti-Inversion Guard (allow-listed `extcodehash` per `contractKey`) + dual SHA-256/BLAKE3 doc hashes → **fail-closed** on tamper.

**Core modules (highlights):**
- **PeaceToken (ERC-20 + Votes + Permit)** — governance & incentives  
- **ReputationSBT (ERC-5484-style)** — non-transferable reputation with decay/slash  
- **QuestEscrow** — mission posting, stakes, verified payouts  
- **AttestRegistry + MilestoneVerifier** — attestation quorums → final Cred(m)  
- **SeasonEngine** — streaks, novelty, jackpots  
- **EthStreamer** — continuous ETH rewards by PIS share  
- **QuadraticPool** — matching funds to broad support  
- **DisputeCourt** — juror selection, appeals, slashing

> Every mutating call in guarded modules includes `ensureIntegrity()`; upgrades must be pre-allowed by the Guard.

---

## 🛡️ Integrity & Safety

- **Anti-Inversion Guard:** `(contractKey, codeHash)` allow-list; upgrades blocked unless allowed.  
- **Dual provenance:** store truncated **SHA-256** + **BLAKE3** of canonical spec/audit.  
- **Zero-Harm License Intent:** humanitarian use only; non-weaponization clause.  
- **Least-privilege roles:** `ADMIN`, `ISSUER/MINTER`, `SLASH/BURNER`, `PAUSER`.

```solidity
require(integrityGuard.isAllowed(contractKey, h), "INTEGRITY"); // fail-closed

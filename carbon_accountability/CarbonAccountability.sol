// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * Global Carbon Accountability Contract
 *
 * Goals:
 * - register supply-chain entities and sensors
 * - accept emission reports (signed by entities / oracles)
 * - accept IoT sensor & satellite verifications (via ORACLE_ROLE)
 * - aggregate and compute verified emissions (scaled integers)
 * - mint tokenized offsets (ERC20) when emissions are verified and offset projects executed
 * - allow retiring offsets and provide dispute/slashing mechanisms
 *
 * Notes:
 * - Off-chain heavy lifting (ML + satellite imagery + sensor fusion) is done by verifiers/oracles.
 * - On-chain we store hashes/pointers and numerical aggregates; proofs are stored off-chain (IPFS) and anchored on-chain.
 * - Use AccessControl to separate roles: GOVERNANCE_ROLE, ORACLE_ROLE, AUDITOR_ROLE, ENTITY_ROLE.
 *
 * Dependencies (OpenZeppelin):
 * - @openzeppelin/contracts/access/AccessControl.sol
 * - @openzeppelin/contracts/token/ERC20/ERC20.sol
 * - @openzeppelin/contracts/security/ReentrancyGuard.sol
 * - @openzeppelin/contracts/utils/cryptography/ECDSA.sol
 *
 * Compile with solc ^0.8.19 and supply proper OpenZeppelin imports in your environment.
 */

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract OffsetToken is ERC20, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external onlyRole(MINTER_ROLE) {
        _burn(from, amount);
    }
}

contract CarbonAccountability is AccessControl, ReentrancyGuard {
    using ECDSA for bytes32;

    // Roles
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE"); // IoT & satellite oracles
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    bytes32 public constant ENTITY_ROLE = keccak256("ENTITY_ROLE");

    // scaling factor for fixed point math (6 decimals)
    uint256 public constant SCALE = 1e6;

    OffsetToken public offsetToken;

    // Bonds: Entities must deposit a bond to submit reports to discourage fraud
    uint256 public submissionBond; // in wei

    // Entity registry
    struct Entity {
        address owner;          // entity on-chain account (could be multisig)
        string name;
        bool exists;
        uint256 bondDeposited;  // wei
        uint256 lastReportId;
    }

    mapping(address => Entity) public entities;

    // Emission report: basic on-chain summary; proofs stored off-chain (IPFS/CID)
    enum ReportStatus { Pending, Verified, Disputed, Rejected }
    struct EmissionReport {
        uint256 id;
        address entity;
        uint256 periodStart;   // unix timestamp
        uint256 periodEnd;     // unix timestamp
        uint256 grossEmissions; // scaled by SCALE (eg 1 TCO2 = 1 * SCALE)
        string proofCID;       // IPFS CID or other pointer to the full proof package
        ReportStatus status;
        address verifier;      // oracle that verified it (if Verified)
        uint256 verifiedAt;    // timestamp
        uint256 confidence;    // 0..SCALE (scale used as 1.000000)
    }

    uint256 public nextReportId;
    mapping(uint256 => EmissionReport) public reports;
    mapping(address => uint256[]) public entityReports;

    // Dispute structure
    struct Dispute {
        uint256 reportId;
        address raisedBy;
        string reasonCID;   // pointer to evidence
        bool resolved;
        bool upheld; // whether dispute upheld (i.e., report rejected)
    }
    uint256 public nextDisputeId;
    mapping(uint256 => Dispute) public disputes;

    // Events
    event EntityRegistered(address indexed entity, string name);
    event BondDeposited(address indexed entity, uint256 amount);
    event EmissionReportSubmitted(uint256 indexed id, address indexed entity, uint256 grossEmissions, string proofCID);
    event ReportVerified(uint256 indexed id, address indexed verifier, uint256 confidence);
    event ReportDisputed(uint256 indexed disputeId, uint256 indexed reportId, address indexed raisedBy);
    event DisputeResolved(uint256 indexed disputeId, bool upheld);
    event OffsetsMinted(uint256 indexed reportId, uint256 amount);
    event OffsetsRetired(address indexed by, uint256 amount);

    // Governance parameters (can be updated by GOVERNANCE_ROLE)
    uint256 public verificationConfidenceThreshold = 800000; // 0.8 scaled
    uint256 public burnRatioOnSlash = 50; // percentage (1..100) to burn on slashing (rest to treasury)
    address payable public treasury;

    constructor(address _offsetToken) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(GOVERNANCE_ROLE, msg.sender);
        offsetToken = OffsetToken(_offsetToken);
        treasury = payable(msg.sender);
        submissionBond = 0.01 ether; // default, change via governance
        nextReportId = 1;
        nextDisputeId = 1;
    }

    // -------------------------
    // Entity lifecycle
    // -------------------------
    function registerEntity(address entityAddress, string calldata name) external onlyRole(GOVERNANCE_ROLE) {
        require(entityAddress != address(0), "zero address");
        require(!entities[entityAddress].exists, "already registered");
        entities[entityAddress] = Entity({
            owner: entityAddress,
            name: name,
            exists: true,
            bondDeposited: 0,
            lastReportId: 0
        });
        grantRole(ENTITY_ROLE, entityAddress);
        emit EntityRegistered(entityAddress, name);
    }

    function depositBond() external payable onlyRole(ENTITY_ROLE) {
        require(msg.value > 0, "no ether");
        entities[msg.sender].bondDeposited += msg.value;
        emit BondDeposited(msg.sender, msg.value);
    }

    function setSubmissionBond(uint256 newBond) external onlyRole(GOVERNANCE_ROLE) {
        submissionBond = newBond;
    }

    function updateTreasury(address payable newTreasury) external onlyRole(GOVERNANCE_ROLE) {
        require(newTreasury != address(0), "zero");
        treasury = newTreasury;
    }

    // -------------------------
    // Submit emission report
    // -------------------------
    // Entities submit compact emission summaries + off-chain proof CID
    function submitEmissionReport(
        uint256 periodStart,
        uint256 periodEnd,
        uint256 grossEmissionsScaled, // scaled by SCALE (e.g., tonnes * SCALE)
        string calldata proofCID
    ) external nonReentrant onlyRole(ENTITY_ROLE) returns (uint256) {
        require(entities[msg.sender].exists, "not registered");
        require(entities[msg.sender].bondDeposited >= submissionBond, "insufficient bond");
        require(periodEnd > periodStart, "bad period");
        uint256 rid = nextReportId++;
        EmissionReport storage r = reports[rid];
        r.id = rid;
        r.entity = msg.sender;
        r.periodStart = periodStart;
        r.periodEnd = periodEnd;
        r.grossEmissions = grossEmissionsScaled;
        r.proofCID = proofCID;
        r.status = ReportStatus.Pending;
        r.confidence = 0;
        entityReports[msg.sender].push(rid);
        entities[msg.sender].lastReportId = rid;
        emit EmissionReportSubmitted(rid, msg.sender, grossEmissionsScaled, proofCID);
        return rid;
    }

    // -------------------------
    // Oracle verification (IoT / Satellite)
    // -------------------------
    // Oracles submit verification outputs after off-chain analytics
    // The on-chain verification should include: report id, verified emissions, confidence (0..SCALE), proofCID
    function verifyReport(
        uint256 reportId,
        uint256 verifiedEmissionsScaled,
        uint256 confidenceScaled,
        string calldata verifierProofCID
    ) external onlyRole(ORACLE_ROLE) {
        EmissionReport storage r = reports[reportId];
        require(r.id != 0, "no report");
        require(r.status == ReportStatus.Pending, "not pending");
        r.verifiedAt = block.timestamp;
        r.verifier = msg.sender;
        r.confidence = confidenceScaled;
        // Basic acceptance criteria: confidence threshold
        if (confidenceScaled >= verificationConfidenceThreshold) {
            r.status = ReportStatus.Verified;
            // Here you might mint offsets or update registry; actual offsets minted by separate function
            emit ReportVerified(reportId, msg.sender, confidenceScaled);
        } else {
            r.status = ReportStatus.Rejected;
            emit ReportVerified(reportId, msg.sender, confidenceScaled);
        }
        // Anchor verifierProofCID for audit trail
        // (r.proofCID already stores submitter proof; we keep verifier proof off chain too)
    }

    // -------------------------
    // Mint offsets (after verified)
    // -------------------------
    // Simple rule: if a verifier confirms removals/offsets, minter (oracle role) can mint tokenized offsets.
    // 1 offset token = 1 TCO2e scaled by SCALE
    function mintOffsets(uint256 reportId, uint256 amountScaled) external onlyRole(ORACLE_ROLE) nonReentrant {
        EmissionReport storage r = reports[reportId];
        require(r.id != 0, "no report");
        require(r.status == ReportStatus.Verified, "not verified");
        // ensure minted amount doesn't exceed reported gross emissions (business rule)
        // This is a policy decision: allow up to grossEmissions or based on separate offset project proofs
        require(amountScaled <= r.grossEmissions, "amount > emissions");
        // Mint to entity by default
        offsetToken.mint(r.entity, amountScaled);
        emit OffsetsMinted(reportId, amountScaled);
    }

    // Retire offsets (burn on-chain and emit event)
    function retireOffsets(uint256 amountScaled) external nonReentrant {
        // Require user to approve this contract as spender or use burn from wrapper role
        // For simplicity, require ENTITY_ROLE caller and burn via offsetToken.burn (which requires MINTER_ROLE)
        // We'll implement a pattern: user transfers tokens to this contract, then contract burns.
        uint256 balanceBefore = offsetToken.balanceOf(address(this));
        // user must transfer tokens to contract before calling retireOffsets
        require(offsetToken.balanceOf(msg.sender) >= amountScaled, "insufficient tokens");
        // pull tokens in
        // need ERC20 approve/transferFrom
        bool ok = IERC20(address(offsetToken)).transferFrom(msg.sender, address(this), amountScaled);
        require(ok, "transfer failed");
        // burn using minter role: contract must have MINTER_ROLE in OffsetToken
        offsetToken.burn(address(this), amountScaled);
        emit OffsetsRetired(msg.sender, amountScaled);
    }

    // -------------------------
    // Dispute mechanism
    // -------------------------
    function raiseDispute(uint256 reportId, string calldata reasonCID) external nonReentrant {
        require(reports[reportId].id != 0, "no report");
        uint256 did = nextDisputeId++;
        disputes[did] = Dispute({
            reportId: reportId,
            raisedBy: msg.sender,
            reasonCID: reasonCID,
            resolved: false,
            upheld: false
        });
        emit ReportDisputed(did, reportId, msg.sender);
    }

    // Auditors resolve disputes. If upheld, report is rejected and slashing may occur
    function resolveDispute(uint256 disputeId, bool uphold, uint256 slashAmountWei) external onlyRole(AUDITOR_ROLE) nonReentrant {
        Dispute storage d = disputes[disputeId];
        require(!d.resolved, "already");
        d.resolved = true;
        d.upheld = uphold;
        EmissionReport storage r = reports[d.reportId];
        if (uphold) {
            // mark report rejected
            r.status = ReportStatus.Rejected;
            // slash entity bond if provided
            address offender = r.entity;
            uint256 bond = entities[offender].bondDeposited;
            uint256 amountToSlash = slashAmountWei <= bond ? slashAmountWei : bond;
            if (amountToSlash > 0) {
                entities[offender].bondDeposited -= amountToSlash;
                uint256 burnAmt = (amountToSlash * burnRatioOnSlash) / 100;
                uint256 toTreasury = amountToSlash - burnAmt;
                if (burnAmt > 0) {
                    // burn by sending to address(0)
                    (bool sent1, ) = address(0).call{value: burnAmt}("");
                    sent1; // purposely ignore result; burning ether isn't meaningful. Better: track slashed tokens. Placeholder.
                }
                if (toTreasury > 0) {
                    (bool sent2, ) = treasury.call{value: toTreasury}("");
                    sent2;
                }
            }
        }
        emit DisputeResolved(disputeId, uphold);
    }

    // -------------------------
    // Admin / Gov setters
    // -------------------------
    function setVerificationConfidenceThreshold(uint256 newThreshold) external onlyRole(GOVERNANCE_ROLE) {
        require(newThreshold <= SCALE, "bad");
        verificationConfidenceThreshold = newThreshold;
    }

    function setBurnRatioOnSlash(uint256 ratioPercent) external onlyRole(GOVERNANCE_ROLE) {
        require(ratioPercent <= 100, "bad");
        burnRatioOnSlash = ratioPercent;
    }

    // -------------------------
    // View helpers
    // -------------------------
    function getEntityReports(address entityAddress) external view returns (uint256[] memory) {
        return entityReports[entityAddress];
    }

    // Allow contract to receive ETH for treasury/bond flows
    receive() external payable {}
    fallback() external payable {}
}

/**
 * Notes & TODOs:
 * - Integrate signature verification for off-chain signed reports (ECDSA) to allow proxy submitters.
 * - Replace ETH-based bond slash logic with stable token or on-chain collateral for better UX.
 * - Add time-windowed dispute deadlines and automatic finalization flows.
 * - Use a more sophisticated math library (ABDK 64.64) if needed for fractional arithmetic.
 * - Consider modular upgradeable pattern (UUPS) if you want upgradability.
 * - Make OffsetToken permissioning tighter: MINTER_ROLE should be granted only to trusted verifiers or to a governance-controlled timelocked multisig.
 */

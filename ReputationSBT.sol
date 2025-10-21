// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IntegrityGuarded.sol";

/**
 * @title ReputationSBT (Pro)
 * @notice Soulbound reputation + badges for verified impact. Integrity-guarded (UUPS-style).
 *
 * Design goals:
 * - Non-transferable badges and a decaying reputation score.
 * - Guarded upgrades: implementation extcodehash must be allow-listed for contractKey.
 * - Fail-closed safety: every state change asserts integrity before execution.
 * - Gas-aware: custom errors, batching, conservative math.
 *
 * Decay model (half-life):
 *   raw(t) → raw(t0) * 2^(-(t - t0)/T), T=halfLifeSeconds
 *   Implementation: integer halvings (>> halves) + first-order remainder using ln(2).
 */
contract ReputationSBT is IntegrityGuarded {
    // --------------------------- Errors (gas-efficient) ---------------------------
    error Unauthorized();
    error Paused();
    error ZeroAddress();
    error ZeroAmount();
    error NoToken();
    error AlreadyRevoked();
    error LengthMismatch();

    // ------------------------------ Roles & Pause -------------------------------
    bytes32 public constant ADMIN_ROLE  = keccak256("ADMIN_ROLE");
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant SLASH_ROLE  = keccak256("SLASH_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private roles;
    bool public paused;

    // ------------------------------ Reputation ----------------------------------
    struct Rep { uint256 raw; uint64 lastUpdate; }
    mapping(address => Rep) private rep;

    // ------------------------------- Badges (SBT) -------------------------------
    string  public  baseURI;
    uint256 public  nextTokenId;              // total issued = nextTokenId
    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => bool)    public revoked;

    // Active SBT accounting (not ERC-721; just a soulbound count of non-revoked)
    mapping(address => uint256) public balanceActive;
    uint256 public activeSupply;

    // --------------------------------- Decay ------------------------------------
    uint64  public halfLifeDays;    // e.g., 30
    uint64  public halfLifeSeconds; // cached for fast math
    // ln(2) scaled by 1e9 for the small-remainder factor approximation
    uint256 private constant LN2_E9 = 693_147_180; // ~0.693147180 * 1e9

    // -------------------------------- Events ------------------------------------
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    event Paused(address indexed by);
    event Unpaused(address indexed by);

    event Issued(address indexed to, uint256 amount, uint256 tokenId, string uri);
    event Slashed(address indexed from, uint256 amount, string reason);
    event Revoked(uint256 indexed tokenId, address indexed from);

    event BaseURISet(string uri);
    event DecaySet(uint64 halfLifeDays);
    event Upgraded(address indexed newImpl);

    bool private _initialized;

    // -------------------------------- Modifiers ---------------------------------
    modifier onlyRole(bytes32 r) {
        if (!roles[r][msg.sender]) revert Unauthorized();
        _;
    }
    modifier whenNotPaused() {
        if (paused) revert Paused();
        _;
    }

    // ------------------------------- Initialize ---------------------------------
    function initialize(
        address admin,
        address guard,
        bytes32 contractKey_,
        bytes32 docHashA_,
        bytes32 docHashB_,
        string memory labelA,
        string memory labelB,
        uint64 halfLifeDays_,
        string memory baseURI_
    ) external {
        if (_initialized) revert Unauthorized();     // simple initializer lock
        if (admin == address(0)) revert ZeroAddress();
        _initialized = true;

        // roles
        _grant(ADMIN_ROLE,  admin);
        _grant(ISSUER_ROLE, admin);
        _grant(SLASH_ROLE,  admin);
        _grant(PAUSER_ROLE, admin);

        // integrity + provenance
        _integrityInit(guard, contractKey_, docHashA_, docHashB_, labelA, labelB);

        // parameters
        _setDecayHalfLifeDays(halfLifeDays_);
        if (bytes(baseURI_).length > 0) {
            baseURI = baseURI_;
            emit BaseURISet(baseURI_);
        }
    }

    // ---------------------------- Role management -------------------------------
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return roles[role][account];
    }

    function grantRole(bytes32 role, address account)
        external
        ensureIntegrity
        onlyRole(ADMIN_ROLE)
    {
        if (account == address(0)) revert ZeroAddress();
        if (!roles[role][account]) {
            roles[role][account] = true;
            emit RoleGranted(role, account);
        }
    }

    function revokeRole(bytes32 role, address account)
        external
        ensureIntegrity
        onlyRole(ADMIN_ROLE)
    {
        if (roles[role][account]) {
            roles[role][account] = false;
            emit RoleRevoked(role, account);
        }
    }

    function renounceRole(bytes32 role)
        external
        ensureIntegrity
    {
        if (roles[role][msg.sender]) {
            roles[role][msg.sender] = false;
            emit RoleRevoked(role, msg.sender);
        }
    }

    // --------------------------------- Pause ------------------------------------
    function pause() external ensureIntegrity onlyRole(PAUSER_ROLE) {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external ensureIntegrity onlyRole(PAUSER_ROLE) {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // --------------------------- Issue / Slash / Revoke -------------------------
    function issue(address to, uint256 amount, string calldata tokenUri)
        external
        ensureIntegrity
        onlyRole(ISSUER_ROLE)
        whenNotPaused
    {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0)       revert ZeroAmount();

        _bumpRep(to, amount, true);

        unchecked { nextTokenId++; }
        uint256 id = nextTokenId;
        ownerOf[id] = to;

        unchecked { balanceActive[to] += 1; activeSupply += 1; }
        emit Issued(to, amount, id, tokenUri);
    }

    function batchIssue(
        address[] calldata to,
        uint256[] calldata amount,
        string[]  calldata tokenUri
    )
        external
        ensureIntegrity
        onlyRole(ISSUER_ROLE)
        whenNotPaused
    {
        if (to.length != amount.length || to.length != tokenUri.length) revert LengthMismatch();
        for (uint256 i; i < to.length; ++i) {
            if (to[i] == address(0)) revert ZeroAddress();
            if (amount[i] == 0)      revert ZeroAmount();

            _bumpRep(to[i], amount[i], true);

            unchecked { nextTokenId++; }
            uint256 id = nextTokenId;
            ownerOf[id] = to[i];

            unchecked { balanceActive[to[i]] += 1; activeSupply += 1; }
            emit Issued(to[i], amount[i], id, tokenUri[i]);
        }
    }

    function slash(address from, uint256 amount, string calldata reason)
        external
        ensureIntegrity
        onlyRole(SLASH_ROLE)
        whenNotPaused
    {
        if (from == address(0)) revert ZeroAddress();
        if (amount == 0)        revert ZeroAmount();

        _bumpRep(from, amount, false);
        emit Slashed(from, amount, reason);
    }

    function batchSlash(
        address[] calldata from,
        uint256[] calldata amount,
        string[]  calldata reason
    )
        external
        ensureIntegrity
        onlyRole(SLASH_ROLE)
        whenNotPaused
    {
        if (from.length != amount.length || from.length != reason.length) revert LengthMismatch();
        for (uint256 i; i < from.length; ++i) {
            if (from[i] == address(0)) revert ZeroAddress();
            if (amount[i] == 0)        revert ZeroAmount();
            _bumpRep(from[i], amount[i], false);
            emit Slashed(from[i], amount[i], reason[i]);
        }
    }

    function revoke(uint256 tokenId)
        external
        ensureIntegrity
        onlyRole(ISSUER_ROLE)
        whenNotPaused
    {
        address holder = ownerOf[tokenId];
        if (holder == address(0)) revert NoToken();
        if (revoked[tokenId])     revert AlreadyRevoked();

        revoked[tokenId] = true;
        // active accounting
        if (balanceActive[holder] > 0) {
            unchecked { balanceActive[holder] -= 1; }
        }
        if (activeSupply > 0) {
            unchecked { activeSupply -= 1; }
        }
        emit Revoked(tokenId, holder);
    }

    // ---------------------------------- Views -----------------------------------
    /**
     * @dev Effective reputation with half-life decay:
     *      halves = dt / T  → integer right-shift
     *      remainder factor ≈ 1 - ln(2) * (rem / T)
     *      Uses 1e9 fixed-point for the remainder factor.
     */
    function reputationOf(address a) public view returns (uint256) {
        Rep memory r = rep[a];
        if (r.raw == 0) return 0;

        uint256 T = uint256(halfLifeSeconds);
        if (T == 0) return r.raw; // should not happen, but be defensive

        uint256 dt     = block.timestamp - uint256(r.lastUpdate);
        uint256 halves = dt / T;
        uint256 rem    = dt % T;

        // apply integer halvings
        uint256 v = r.raw >> halves;
        if (v == 0) return 0;

        // remainder factor ≈ 2^(-rem/T) ≈ 1 - ln(2) * rem / T   (1e9 scale)
        uint256 factorE9 = 1_000_000_000 - (LN2_E9 * rem) / T;
        // clamp to zero if negative would occur (shouldn’t under uint math)
        if (factorE9 == 0) return 0;

        return (v * factorE9) / 1_000_000_000;
    }

    function tokenURI(uint256 tokenId) external view returns (string memory) {
        if (ownerOf[tokenId] == address(0)) revert NoToken();
        if (bytes(baseURI).length == 0) return "";
        return string(abi.encodePacked(baseURI, _toString(tokenId)));
    }

    function totalIssued() external view returns (uint256) {
        return nextTokenId;
    }

    // ------------------------------ Admin params --------------------------------
    function setBaseURI(string calldata u)
        external
        ensureIntegrity
        onlyRole(ADMIN_ROLE)
    {
        baseURI = u;
        emit BaseURISet(u);
    }

    function setDecayHalfLifeDays(uint64 d)
        external
        ensureIntegrity
        onlyRole(ADMIN_ROLE)
    {
        _setDecayHalfLifeDays(d);
    }

    function setDocumentHashes(
        bytes32 a,
        bytes32 b,
        string calldata la,
        string calldata lb
    )
        external
        ensureIntegrity
        onlyRole(ADMIN_ROLE)
    {
        // provenance rotation (e.g., new spec/audit doc)
        docHashA = a; docHashB = b; docLabelA = la; docLabelB = lb;
        emit DocumentHashesSet(a, b, la, lb);
    }

    // ------------------------------ Upgrade (UUPS) ------------------------------
    function upgradeTo(address newImpl)
        external
        onlyRole(ADMIN_ROLE)
    {
        if (newImpl == address(0)) revert ZeroAddress();
        bytes32 h; assembly { h := extcodehash(newImpl) }
        // Integrity: require allow-listed impl code hash for our contractKey
        require(integrityGuard.isAllowed(contractKey, h), "INTEGRITY");

        // EIP-1967 impl slot
        bytes32 slot =
            0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly { sstore(slot, newImpl) }
        emit Upgraded(newImpl);
    }

    // -------------------------------- Internals ---------------------------------
    function _bumpRep(address a, uint256 amt, bool add) internal {
        Rep storage r = rep[a];
        uint256 current = reputationOf(a);
        r.raw = add
            ? current + amt
            : (current > amt ? current - amt : 0);
        r.lastUpdate = uint64(block.timestamp);
    }

    function _setDecayHalfLifeDays(uint64 d) internal {
        halfLifeDays = d == 0 ? 30 : d;
        halfLifeSeconds = halfLifeDays * 86400;
        emit DecaySet(halfLifeDays);
    }

    function _toString(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 j = v; uint256 len;
        while (j != 0) { len++; j /= 10; }
        bytes memory b = new bytes(len);
        j = v; uint256 k = len;
        while (j != 0) { k--; b[k] = bytes1(uint8(48 + j % 10)); j /= 10; }
        return string(b);
    }

    // ------------------------------- Convenience --------------------------------
    function version() external pure returns (string memory) {
        return "ReputationSBT/2.1.0-pro";
    }
}

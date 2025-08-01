// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

/* -------------------------------------------------------------------------- */
/*  ERC-1271 interface                                                        */
/* -------------------------------------------------------------------------- */
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
}

/* -------------------------------------------------------------------------- */
/*  ERC-7579 helper interface (only the call we need)                          */
/* -------------------------------------------------------------------------- */
interface IERC7579Account {
    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext)
        external
        view
        returns (bool);
}

/* -------------------------------------------------------------------------- */
/*  Subset of Gnosis Safe owner-management interface                           */
/*  (only selectors whitelisted by UniversalEmailRecoveryModule)               */
/* -------------------------------------------------------------------------- */
interface ISafeLike {
    function addOwnerWithThreshold(address owner, uint256 threshold) external;
    function removeOwner(address prevOwner, address owner, uint256 threshold) external;
    function swapOwner(address prevOwner, address oldOwner, address newOwner) external;
    function changeThreshold(uint256 threshold) external;
}

/* -------------------------------------------------------------------------- */
/*  Minimal smart-wallet compatible with ZKEmail UniversalEmailRecoveryModule  */
/* -------------------------------------------------------------------------- */
contract MinimalAccount is IERC7579Account, ISafeLike, IERC1271 {
    /* --------------------------- ERC-1271 constants ------------------------ */
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    
    /* --------------------------- ERC-7579 constants ------------------------ */
    uint256 internal constant TYPE_VALIDATOR = 1; // validator module type-id

    /* -------------------------------- Storage ----------------------------- */
    address public owner;
    address public immutable recoveryModule;

    /* -------------------------------- Events ------------------------------ */
    event Executed(address indexed target, uint256 value, bytes data, bytes result);
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);

    /* -------------------------------- Mods -------------------------------- */
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyRecoveryModule() {
        require(msg.sender == recoveryModule, "Not recovery module");
        _;
    }

    /* ----------------------------- Constructor ---------------------------- */
    constructor(address _initialOwner, address _recoveryModule) {
        require(_initialOwner != address(0), "owner=0");
        require(_recoveryModule != address(0), "module=0");
        owner = _initialOwner;
        recoveryModule = _recoveryModule;
    }

    /* --------------------------- ERC-1271 Support ------------------------- */
    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes memory signature) 
        external 
        view 
        override 
        returns (bytes4 magicValue) 
    {
        // Recover the signer from the signature
        address recoveredSigner = ECDSA.recover(hash, signature);
        
        // Check if the recovered signer is the current owner
        if (recoveredSigner == owner) {
            return MAGICVALUE;
        }
        
        // Invalid signature
        return 0xffffffff;
    }

    /* ------------------------- ERC-7579 registry -------------------------- */
    /// @inheritdoc IERC7579Account
    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata)
        external
        view
        override
        returns (bool)
    {
        // Wallet self-declares as an always-installed validator
        return moduleTypeId == TYPE_VALIDATOR && module == address(this);
    }

    /* ------------------------- General execution -------------------------- */
    function executeCall(address target, uint256 value, bytes calldata data)
        external
        onlyOwner
        returns (bytes memory result)
    {
        require(target != address(0), "target=0");
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        emit Executed(target, value, data, ret);
        return ret;
    }

    /* -------------------------- Owner management -------------------------- */
    function _setOwner(address newOwner) internal {
        require(newOwner != address(0), "newOwner=0");
        address prev = owner;
        owner = newOwner;
        emit OwnerChanged(prev, newOwner);
    }

    /* ——— Legacy "recover" wrapper (not used by module once Safe selector used) */
    function recover(address newOwner) external onlyRecoveryModule {
        _setOwner(newOwner);
    }

    /* ---------------- Safe-compatible hooks accepted by UERM -------------- */
    /// @inheritdoc ISafeLike
    function addOwnerWithThreshold(address newOwner, uint256) external onlyRecoveryModule {
        _setOwner(newOwner);
    }

    /// The remaining Safe functions are stubbed-out (module never calls them)
    function removeOwner(address, address, uint256) external pure {
        revert("NIY");
    }

    function swapOwner(address, address, address) external pure {
        revert("NIY");
    }

    function changeThreshold(uint256) external pure {
        revert("NIY");
    }

    function onInstall(bytes calldata data) external pure {
        revert("NIY");
    }

    /* ------------------------ Ether reception ----------------------------- */
    receive() external payable {}
    fallback() external payable {}
}
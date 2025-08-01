// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import "lib/forge-std/src/StdJson.sol";
import {EmailAuthMsg, EmailProof} from "test/Structs.sol";

interface IUniversalEmailRecoveryModule {
    function onInstall(bytes calldata data) external;
}

interface IEmailRecoveryModule {
    function computeAcceptanceTemplateId(uint256 templateIdx) external pure returns (uint256);

    function computeRecoveryTemplateId(uint256 templateIdx) external pure returns (uint256);

    function handleAcceptance(EmailAuthMsg memory emailAuthMsg, uint256 templateIdx) external;

    function handleRecovery(EmailAuthMsg memory emailAuthMsg, uint256 templateIdx) external;

    function completeRecovery(address account, bytes memory completeCalldata) external;
}

import {MinimalAccount} from "src/Account.sol";
import {Test} from "lib/forge-std/src/Test.sol";

contract Base is Test {
    address public owner;
    uint256 public ownerPK;
    address public relay;

    string public json_emails = vm.readFile("script/data/emails.json");
    string public json_addresses = vm.readFile("script/data/addresses.json");
    string public json_guardians_addresses = vm.readFile("script/data/guardians_computed_addrs.json");
    address public recoveryModule = stdJson.readAddress(json_addresses, ".UniversalEmailRecoveryModule");
    string public constant domainName = "gmail.com";

    MinimalAccount acc;

    uint256 internal forkId;
    string internal SEPOLIA_RPC = "https://sepolia.drpc.org";

    uint256 constant DELAY = 6 hours;
    uint256 constant EXPIRY = 7 days;

    string[] eMails;
    bytes32[] SALT;
    bytes32[] ACCOUNT_CODE;
    uint256 public nullifierCount;

    function setUp() public virtual {
        forkId = vm.createFork(SEPOLIA_RPC);
        vm.selectFork(forkId);

        (owner, ownerPK) = makeAddrAndKey("owner");
        relay = makeAddr("relay");  
        acc = new MinimalAccount(owner, recoveryModule);
        eMails.push(stdJson.readString(json_emails, ".guardian_0"));
        eMails.push(stdJson.readString(json_emails, ".guardian_1"));
        eMails.push(stdJson.readString(json_emails, ".guardian_2"));

        ACCOUNT_CODE.push(keccak256(abi.encode("account salt 1")));
        ACCOUNT_CODE.push(keccak256(abi.encode("account salt 2")));
        ACCOUNT_CODE.push(keccak256(abi.encode("account salt 3")));
    }

    function deal() internal {
        vm.deal(owner, 10e18);
        vm.deal(relay, 10e18);
    }

    function generateMockEmailProof(string memory command, bytes32 nullifier, bytes32 accountSalt)
        public
        pure
        returns (EmailProof memory)
    {
        EmailProof memory emailProof;
        emailProof.domainName = domainName;
        emailProof.publicKeyHash = hex"954fe49f513df570cfae5648a161bea3b81ed67ce88199f802a0bfafa4899b95";
        emailProof.timestamp = 1752228781;
        emailProof.maskedCommand = command;
        emailProof.emailNullifier = nullifier;
        emailProof.accountSalt = accountSalt;
        emailProof.isCodeExist = true;
        emailProof.proof =
            hex"7ce723b8158596637bfaac01c828a34c012af7a1b210337b4a615cda71ef6018707d66de3985229e5465adabc92d2b65bfb4619a2d659404d50ffffadfa8aeefb2f3da43d83686b8f19dd71f37fefecd4f2a3413e74dd2508af22f132ae72d75338af6006e38548e2c12e7604f69e5972395c6cf92aa2ac1f968830b771ef73938e7dccf4c26499fad6faef5005c0a74cd664a9247a42cbd79d983bf8bc5bd4af6219c2ab74698ce0fea318f7197f1f712507f43d9f167ebce4e0c172ea1b92dfd4cef5b7a39fac3c4c09b24b208e15a2b74d3e196258ded10ea9cfaac733849cb54ce907400f277d364bdeeb83f35f505bf266bf14973e54afd447f7798dbc7";

        return emailProof;
    }

    function parseGuardiansAddresses() public view returns (address[] memory guardiansAddresses) {
        guardiansAddresses = new address[](eMails.length);

        for (uint256 i = 0; i < eMails.length;) {
            string memory eMail = eMails[i];

            // Use bracket notation to handle keys with dots
            string memory jsonPath = string.concat('["', eMail, '"]');
            guardiansAddresses[i] = stdJson.readAddress(json_guardians_addresses, jsonPath);

            unchecked {
                ++i;
            }
        }
    }

    function generateNewNullifier() public returns (bytes32) {
        return keccak256(abi.encode(nullifierCount++));
    }
}

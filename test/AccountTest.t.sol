// SPDX-License-Identifier: MIR

pragma solidity ^0.8.29;


import {Base} from "test/Base.t.sol";
import {Helpers} from "test/Helpers.sol";
import {IEmailRecoveryModule} from "test/Base.t.sol";
import {CommandUtils} from "test/libs/CommandUtils.sol";
import {EmailAuthMsg, EmailProof} from "test/Structs.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";

contract AccountTest is Base, Helpers {
    address validator; 
    bytes isInstalledContext; 
    bytes4 initialSelector;
    address[] guardians;
    uint256[] weights;
    uint256 threshold;
    uint256 delay;
    uint256 expiry;

    function setUp() public override {
        super.setUp();
    }

    function test_AfterDeploy() external view {
        console.log("address(acc):", address(acc));
        address ownerAfter = acc.owner();
        address recoveryModuleAfter = acc.recoveryModule();

        assertEq(ownerAfter, owner);
        assertEq(recoveryModuleAfter, recoveryModule);
    }

    function test_ForkId() external view {
        uint256 forkIdFromBlock = block.chainid;
        console.log("forkIdFromBlock", forkIdFromBlock);
        assertEq(11155111, forkIdFromBlock);
    }

    function test_IsDKIMPublicKeyHashValid() external SetDKIM {
        string memory command;
        string memory accountString = CommandUtils.addressToChecksumHexString(address(acc));
        command = string.concat("Accept guardian request for ", accountString);
        bytes32 nullifier = generateNewNullifier();
        EmailProof memory emailProof = generateMockEmailProof(command, nullifier, keccak256(abi.encode("g_1_test")));
        bool res = isDKIMPublicKeyHashValid(emailProof.domainName, emailProof.publicKeyHash);
        console.log("res", res);
    }

    function test_VerifyEmailProof() external SetDKIM {
        EmailProof memory proof = EmailProof({
            domainName: "gmail.com",
            publicKeyHash: hex"026a67ded81b8366f6713679db806b12804fc98936e15aa75aa659e99fafc6ef",
            timestamp: 1752247207,
            maskedCommand: "Accept guardian request for 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f",
            emailNullifier: hex"ae99ca34f91a0d20ac931c411ce640471004cc8b6a55ecacba4eb926f4dddbdd",
            accountSalt: hex"fb010cd5b74b13e9faf1026bee26edbf6d7a539d6ea2edca7aa0189a1b1653fd",
            isCodeExist: false,
            proof: hex"0d32ffc1e6f0cb8cde7c3f32f3850abf3ee943c390071bc14d0f21c0ee6a165f2c83f9ee448c5f141408ac383915c26ea382ab5e049b71ad2eb5bd5cf553721901eff82df6b0cbbe30ed5067ce4a30c99dcb136938ebc12512ee870dd776b3c22574513e2a99b57c5f9f315ecee349f2c32b6aac19fd3ac657e960b97ee118c611fa15c51425f3da31a78f83f38930050fc7d09c4a7daa7709d2646e2df966a22a13a5f2017f0403ab0873f565315023cfac8e63f88108088833851c0c8fc09d09bb0d35cf8a2383af94e86b0156c6dafa97cb312e167140a7e384f47c1514d91352076282772b8b13dd70439c35062bfc2265f53033c5dc4f1bcef7bf6dfc9c"
        });

        verifyEmailProof(proof);
    }

    function test_OnInstall() external OnInstal {
        bytes memory call = abi.encodeWithSignature("getGuardianConfig(address)", address(acc));

        (, bytes memory res) = recoveryModule.staticcall(call);
        (uint256 guardianCount, uint256 totalWeight, uint256 acceptedWeight, uint256 thresholdRes) =
            abi.decode(res, (uint256, uint256, uint256, uint256));

        assertEq(guardianCount, eMails.length);
        assertEq(totalWeight, eMails.length);
        assertEq(acceptedWeight, 0);
        assertEq(thresholdRes, threshold);
        _acceptanceCommandTemplates();
    }

    function test_AcceptGuardian() external OnInstal SetDKIM {
        uint256 templateIdx = 0;
        string memory command;
        bytes[] memory commandParamsForAcceptance = new bytes[](1);

        string memory accountString = CommandUtils.addressToChecksumHexString(address(acc));
        command = string.concat("Accept guardian request for ", accountString);
        commandParamsForAcceptance[0] = abi.encode(address(acc));

        bytes32 nullifier = generateNewNullifier();

        bytes32 accountSalt = SALT[0];

        EmailProof memory emailProof = generateMockEmailProof(command, nullifier, accountSalt);

        EmailAuthMsg memory emailAuthMsg = EmailAuthMsg({
            templateId: IEmailRecoveryModule(recoveryModule).computeAcceptanceTemplateId(templateIdx),
            commandParams: commandParamsForAcceptance,
            skippedCommandPrefix: 0,
            proof: emailProof
        });

        bool isDkimRegistered = getDkimPublicKeyHashes(domainName, emailProof.publicKeyHash, address(acc));
        console.log("isDkimRegistered", isDkimRegistered);  
        assertTrue(isDkimRegistered, "DKIM not registered");

        bytes memory callData =
            abi.encodeWithSelector(IEmailRecoveryModule.handleAcceptance.selector, emailAuthMsg, templateIdx);

        _execute(callData);
    }

    function _execute(bytes memory callData) internal {
        vm.startPrank(owner);
        acc.executeCall(acc.recoveryModule(), 0e18, callData);
        vm.stopPrank();
    }

    function _onInstallCallData() internal returns (bytes memory callData) {
        validator = address(acc);
        isInstalledContext = hex"";
        initialSelector = acc.onInstall.selector;
        delay = DELAY;
        expiry = EXPIRY;
        threshold = 1;

        guardians = new address[](eMails.length);
        weights = new uint256[](eMails.length);

        for (uint256 i = 0; i < eMails.length;) {
            guardians[i] = _computeEmailAddress(eMails[i], ACCOUNT_CODE[i]);
            weights[i] = 1;

            unchecked {
                ++i;
            }
        }

        // Properly encode the data that onInstall expects
        bytes memory data = abi.encode(
            validator, // address
            isInstalledContext, // bytes
            initialSelector, // bytes4
            guardians, // address[]
            weights, // uint256[]
            threshold, // uint256
            delay, // uint256
            expiry // uint256
        );

        // Encode the function call with the data
        callData = abi.encodeWithSignature("onInstall(bytes)", data);
    }

    function _computeEmailAddress(string memory eMail, bytes32 accountCode) internal returns (address addr) {
        bytes32 hash = _hashEmail({eMail: eMail, accountCode: accountCode});
        SALT.push(hex"587cead1cd47a0fd578088a8756b9c50578f6f4f1ebf14cba88bff6f45015500");
        bytes memory call = abi.encodeWithSignature("computeEmailAuthAddress(address,bytes32)", address(acc), hash);

        (, bytes memory res) = recoveryModule.staticcall(call);
        addr = abi.decode(res, (address));
        console.log("Email Address %s:", eMail, addr);
        console.logBytes32(hash);
    }

    function _hashEmail(string memory eMail, bytes32 accountCode) internal pure returns (bytes32 hash) {
        hash = keccak256(abi.encode(eMail, accountCode));
    }

    function _acceptanceCommandTemplates() internal view {
        bytes memory call = abi.encodeWithSignature("acceptanceCommandTemplates()");

        (, bytes memory res) = recoveryModule.staticcall(call);
        string[][] memory templates = abi.decode(res, (string[][]));
        for (uint256 i = 0; i < templates[0].length;) {
            console.log(templates[0][i]);
            unchecked {
                ++i;
            }
        }
    }

    function setDKIM() public {
        bytes32 publicKeyHash = hex"026a67ded81b8366f6713679db806b12804fc98936e15aa75aa659e99fafc6ef";
        bytes32 hashToSign = createDigest(domainName, publicKeyHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, hashToSign);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(owner);
        setDKIMPublicKeyHash(domainName, publicKeyHash, address(acc), signature);
    }

    modifier SetDKIM() {
        setDKIM();
        _;
    }

    modifier OnInstal() {
        bytes memory callData = _onInstallCallData();
        _execute({callData: callData});
        _;
    }
}

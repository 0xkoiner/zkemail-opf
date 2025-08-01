// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import "lib/openzeppelin-contracts/contracts/utils/Strings.sol";
import {EmailAuthMsg, EmailProof} from "test/Structs.sol";
import {MessageHashUtils} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

interface IDKIMRegistry {
    function dkimPublicKeyHashes(
        string memory domainName, 
        bytes32 publicKeyHash, 
        address authorizer
    ) external view returns (bool);

    function isDKIMPublicKeyHashValid(string memory domainName, bytes32 publicKeyHash) external view returns (bool);

    function setDKIMPublicKeyHash(
        string memory domainName,
        bytes32 publicKeyHash,
        address authorizer,
        bytes memory signature
    ) external;
}

interface IVerifier {
    function commandBytes() external view returns (uint256);

    function verifyEmailProof(
        EmailProof memory proof
    ) external view returns (bool);
}

contract Helpers {
    using Strings for *;

    address constant DKIM = 0x3D3935B3C030893f118a84C92C66dF1B9E4169d6;
    address constant VERIFIER = 0x3E5f29a7cCeb30D5FCD90078430CA110c2985716;
    string public constant SET_PREFIX = "SET:";

    function isDKIMPublicKeyHashValid(string memory domainName, bytes32 publicKeyHash) public view returns (bool) {
        return IDKIMRegistry(DKIM).isDKIMPublicKeyHashValid(domainName, publicKeyHash);
    }

    function setDKIMPublicKeyHash(
        string memory domainName,
        bytes32 publicKeyHash,
        address authorizer,
        bytes memory signature
    ) public {
        IDKIMRegistry(DKIM).setDKIMPublicKeyHash(domainName, publicKeyHash, authorizer, signature);
    }

    function computeSignedMsg(string memory prefix, string memory domainName, bytes32 publicKeyHash)
        public
        pure
        returns (string memory)
    {
        return
            string.concat(prefix, "domain=", domainName, ";public_key_hash=", uint256(publicKeyHash).toHexString(), ";");
    }

    function createDigest(string memory domainName, bytes32 publicKeyHash) public pure returns (bytes32 digest) {
        string memory signedMsg = computeSignedMsg(SET_PREFIX, domainName, publicKeyHash);
        digest = MessageHashUtils.toEthSignedMessageHash(bytes(signedMsg));
    }

    function getDkimPublicKeyHashes(string memory domainName, bytes32 publicKeyHash, address authorizer)
        public
        view
        returns (bool)
    {
        return IDKIMRegistry(DKIM).dkimPublicKeyHashes(domainName, publicKeyHash, authorizer);
    }

    function verifyEmailProof(EmailProof memory proof) public view returns (bool) {
        return IVerifier(VERIFIER).verifyEmailProof(proof);
    }
}

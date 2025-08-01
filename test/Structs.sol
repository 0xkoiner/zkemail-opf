// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

/// @notice Struct to hold the email authentication/authorization message.
struct EmailAuthMsg {
    /// @notice The ID of the command template that the command in the email body should satisfy.
    uint256 templateId;
    /// @notice The parameters in the command of the email body, which should be taken according to the specified command template.
    bytes[] commandParams;
    /// @notice The number of skipped bytes in the command.
    uint256 skippedCommandPrefix;
    /// @notice The email proof containing the zk proof and other necessary information for the email verification by the verifier contract.
    EmailProof proof;
}

struct EmailProof {
    string domainName; // Domain name of the sender's email
    bytes32 publicKeyHash; // Hash of the DKIM public key used in email/proof
    uint256 timestamp; // Timestamp of the email
    string maskedCommand; // Masked command of the email
    bytes32 emailNullifier; // Nullifier of the email to prevent its reuse.
    bytes32 accountSalt; // Create2 salt of the account
    bool isCodeExist; // Check if the account code is exist
    bytes proof; // ZK Proof of Email
}

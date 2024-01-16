// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.17;

/// @title Signature verification
/// @author Varun Doshi
/// @notice Contract used to verify message signed

contract Signature {
    /*for signing;
        - message hash
        

    for verifying:
        - ethsigned message hash
        - signature
        - address
        - v,r,s
    */

    /// @notice Main function to verify the signature
    /// @dev Verifies if sig is signed by intended address
    /// @param message string that was passed into the signature
    /// @param amount amount that was passed into the signature
    /// @param signature byets32 representation of the signature
    /// @param signer address that needs to be validated
    function verify(
        string memory message,
        uint256 amount,
        bytes memory signature,
        address signer
    ) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(message, amount);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        (uint8 v, bytes32 r, bytes32 s) = split(signature);
        address _signer = ecrecover(ethSignedMessageHash, v, r, s);

        return _signer == signer;
    }

    
    /// @dev Split the sig into its components v,r,s
    /// @param _sig signature that needs to be authenticated)
    function split(
        bytes memory _sig
    ) public pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(_sig.length == 65, "Signature not right!");

        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            v := byte(0, mload(add(_sig, 96)))
        }
    }

    ///@return returns the keccak256 hash of the message
    function getMessageHash(
        string memory message,
        uint256 amount
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(message, amount));
    }

    ///@dev converts message to format Ethereum uses to sign message
    function getEthSignedMessageHash(
        bytes32 messageHash
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    messageHash
                )
            );
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "../lib/forge-std/src/Test.sol";
import {console} from "../lib/forge-std/src/console.sol";
import {Signature} from "../src/Signature.sol";
import {SignatureScript} from "../script/SignatureScript.s.sol";
import "../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract SignatureTest is Test {
    using ECDSA for bytes32;
    Signature public signature;
    SignatureScript public deployer;

    function setUp() public {
        deployer=new SignatureScript();
        signature = deployer.run();
    }

    function test_ECDSA() public {
        (address bob, uint256 key) = makeAddrAndKey("bob");
        console.log(address(bob));
        string memory message = "Use only for emergencies";
        uint256 amount = 5 ether;

        bytes32 messageHash = signature.getMessageHash(message, amount);
        bytes32 ethSignedMessageHash = signature.getEthSignedMessageHash(
            messageHash
        );

        vm.startPrank(bob);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethSignedMessageHash);

        bytes memory sig = abi.encodePacked(r, s, v);

        bool validSig = signature.verify(message, amount, sig, address(bob));

        assertEq(validSig, true);
    }

    function test_signature_maleability() public {

        (address bob, uint256 key) = makeAddrAndKey("bob");
        string memory message = "Use only for emergencies";
        uint256 amount = 5 ether;

        bytes32 messageHash = signature.getMessageHash(message, amount);
        bytes32 ethSignedMessageHash = signature.getEthSignedMessageHash(
            messageHash
        );

        vm.startPrank(bob);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethSignedMessageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes32 groupOrder = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 invertedS = bytes32(uint256(groupOrder) - uint256(s));
        uint8 invertedV = v == 27 ? 28 : 27;
        bytes32 _r = r;

        bytes memory sig2 = abi.encodePacked(_r, invertedS, invertedV);

        bool validSig = signature.verify(message, amount, sig, address(bob));
        console.log(validSig);

        bool validSig2 = signature.verify(message, amount, sig2, address(bob));
        console.log(validSig2);
    }

    function test_fuzz_ECDSA(uint256 amount) public {
        (address bob, uint256 key) = makeAddrAndKey("bob");
        string memory message = "Use only for emergencies";

        bytes32 messageHash = signature.getMessageHash(message, amount);
        bytes32 ethSignedMessageHash = signature.getEthSignedMessageHash(
            messageHash
        );

        vm.startPrank(bob);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethSignedMessageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bool validSig = signature.verify(message, amount, sig, address(bob));

        assertEq(validSig, true);
    }
}

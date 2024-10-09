// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {InvalidSignatureRecoveredZeroAddress} from "../common/Errors.sol";
import {Signature, Agent} from "../common/Structs.sol";

library SignatureLibrary {
    using ECDSA for bytes32;

    bytes32 private constant EIP712_DOMAIN_SEPARATOR =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 private constant AGENT_TYPEHASH =
        keccak256("Agent(string source,bytes32 connectionId)");

    function makeDomainSeparator() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    EIP712_DOMAIN_SEPARATOR,
                    keccak256(bytes("DefxBridge")),
                    keccak256(bytes("1")),
                    block.chainid,
                    address(this)
                )
            );
    }

    function recoverSigner(
        bytes32 dataHash,
        Signature memory sig,
        bytes32 domainSeparator
    ) internal pure returns (address) {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, dataHash)
        );

        bytes memory signature = abi.encodePacked(sig.r, sig.s, sig.v);
        return ECDSA.recover(digest, signature);
    }

    function generateUniqueMessageHash(
        bytes32 data,
        address contractAddress
    ) internal pure returns (bytes32) {
        Agent memory agent = Agent(
            "a",
            keccak256(abi.encode(address(contractAddress), data))
        );
        return
            keccak256(
                abi.encode(
                    AGENT_TYPEHASH,
                    keccak256(bytes(agent.source)),
                    agent.connectionId
                )
            );
    }
}

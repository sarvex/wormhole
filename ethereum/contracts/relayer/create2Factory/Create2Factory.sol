// SPDX-License-Identifier: Apache 2

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Create2.sol";

/**
 * Contract factory that facilitates predfictable deployment addresses
 */
contract Create2Factory {
    function create(bytes32 userSalt, bytes memory bytecode) external payable returns (address) {
        return Create2.deploy(msg.value, salt(msg.sender, userSalt), bytecode);
    }

    function computeAddress(address creator, bytes32 userSalt, bytes32 bytecodeHash) public view returns (address) {
        return Create2.computeAddress(salt(creator, userSalt), bytecodeHash);
    }

    function salt(address creator, bytes32 userSalt) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(creator, userSalt));
    }
}

// SPDX-License-Identifier: Apache 2

pragma solidity ^0.8.0;

import "../../interfaces/IWormhole.sol";
import "../../interfaces/relayer/IRelayProvider.sol";
import "../../interfaces/relayer/IWormholeRelayerInternalStructs.sol";

import "./CoreRelayerState.sol";
import "../../libraries/external/BytesLib.sol";

abstract contract CoreRelayerGetters is CoreRelayerState {
    using BytesLib for bytes;

    // immutable var set in implementation, not proxy state
    address immutable forwardWrapper;

    constructor(address _forwardWrapper) {
        forwardWrapper = _forwardWrapper;
    }

    function governanceActionIsConsumed(bytes32 hash) public view returns (bool) {
        return _state.consumedGovernanceActions[hash];
    }

    function governanceChainId() public view returns (uint16) {
        return _state.provider.governanceChainId;
    }

    function governanceContract() public view returns (bytes32) {
        return _state.provider.governanceContract;
    }

    function isInitialized(address impl) public view returns (bool) {
        return _state.initializedImplementations[impl];
    }

    function wormhole() public view returns (IWormhole) {
        return IWormhole(_state.provider.wormhole);
    }

    function chainId() public view returns (uint16) {
        return _state.provider.chainId;
    }

    function evmChainId() public view returns (uint256) {
        return _state.evmChainId;
    }

    function isFork() public view returns (bool) {
        return evmChainId() != block.chainid;
    }

    function registeredCoreRelayerContract(uint16 chain) public view returns (bytes32) {
        return _state.registeredCoreRelayerContract[chain];
    }

    function defaultRelayProvider() internal view returns (address) {
        return _state.defaultRelayProvider;
    }

    function getForwardInstructions()
        public
        view
        returns (IWormholeRelayerInternalStructs.ForwardInstruction[] memory)
    {
        return _state.forwardInstructions;
    }

    function getWormholeRelayerCallerAddress() public view returns (address) {
        return forwardWrapper;
    }

    function isContractLocked() internal view returns (bool) {
        return _state.contractLock;
    }

    function lockedTargetAddress() internal view returns (address) {
        return _state.targetAddress;
    }
}

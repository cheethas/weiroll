// SPDX-License-Identifier: MIT

pragma solidity ^0.8.11;

import "./CommandBuilder.sol";

abstract contract VM {
  using CommandBuilder for bytes[];

  uint256 constant FLAG_CT_DELEGATECALL = 0x00;
  uint256 constant FLAG_CT_CALL = 0x01;
  uint256 constant FLAG_CT_STATICCALL = 0x02;
  uint256 constant FLAG_CT_VALUECALL = 0x03;
  uint256 constant FLAG_CT_MASK = 0x03;
  uint256 constant FLAG_EXTENDED_COMMAND = 0x80;
  uint256 constant FLAG_TUPLE_RETURN = 0x40;

  uint256 constant SHORT_COMMAND_FILL =
    0x000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

  address immutable self;

  error ExecutionFailed(uint256 command_index, address target, string message);

  constructor() {
    self = address(this);
  }

  function _execute(
    bytes32[] calldata commands,
    bytes[] memory state
  ) internal returns (bytes[] memory) {
    bytes32 command;
    uint256 flags;
    bytes32 indices;

    bool success;
    bytes memory outdata;

    uint256 commandsLength = commands.length;
    for (uint256 i; i < commandsLength; ) {
      command = commands[i];
      flags = uint256(uint8(bytes1(command << 32)));

      if (flags & FLAG_EXTENDED_COMMAND != 0) {
        indices = commands[i++];
      } else {
        indices = bytes32(uint256(command << 40) | SHORT_COMMAND_FILL);
      }

      // Base function pointer to use
      function(bytes[] memory, bytes32, bytes32)
        returns (bool, bytes memory) callfunc;

      uint256 functionTable;
      assembly {
        functionTable := mload(0x40)
        mstore(0x40, add(functionTable, 0x80))
      }
      {
        // Make function pointers available in asm
        function(bytes[] memory, bytes32, bytes32)
          returns (bool, bytes memory) j0 = delegate_call;
        function(bytes[] memory, bytes32, bytes32)
          returns (bool, bytes memory) j1 = call;
        function(bytes[] memory, bytes32, bytes32)
          returns (bool, bytes memory) j2 = static_call;
        function(bytes[] memory, bytes32, bytes32)
          returns (bool, bytes memory) j3 = value_call;

        // Create jump table copy pointers into mem
        assembly {
          mstore(functionTable, j0)
          mstore(add(functionTable, 0x20), j1)
          mstore(add(functionTable, 0x40), j2)
          mstore(add(functionTable, 0x60), j3)
        }
      }

      // Get jump offset
      uint256 tableIndex = flags & FLAG_CT_MASK;
      assembly {
        callfunc := mload(add(functionTable, shl(5, tableIndex)))
      }

      // Call function
      (success, outdata) = callfunc(state, command, indices);

      if (!success) {
        if (outdata.length > 0) {
          assembly {
            outdata := add(outdata, 68)
          }
        }
        revert ExecutionFailed({
          command_index: 0,
          target: address(uint160(uint256(command))),
          message: outdata.length > 0 ? string(outdata) : "Unknown"
        });
      }

      if (flags & FLAG_TUPLE_RETURN != 0) {
        state.writeTuple(bytes1(command << 88), outdata);
      } else {
        state = state.writeOutputs(bytes1(command << 88), outdata);
      }
      unchecked {
        ++i;
      }
    }
    return state;
  }

  function delegate_call(
    bytes[] memory state,
    bytes32 command,
    bytes32 indices
  ) internal returns (bool success, bytes memory outdata) {
    (success, outdata) = address(uint160(uint256(command))).delegatecall( // target
      // inputs
      state.buildInputs(
        //selector
        bytes4(command),
        indices
      )
    );
  }

  function call(
    bytes[] memory state,
    bytes32 command,
    bytes32 indices
  ) internal returns (bool success, bytes memory outdata) {
    (success, outdata) = address(uint160(uint256(command))).call( // target
      // inputs
      state.buildInputs(
        //selector
        bytes4(command),
        indices
      )
    );
  }

  function static_call(
    bytes[] memory state,
    bytes32 command,
    bytes32 indices
  ) internal returns (bool success, bytes memory outdata) {
    (success, outdata) = address(uint160(uint256(command))).staticcall( // target
      // inputs
      state.buildInputs(
        //selector
        bytes4(command),
        indices
      )
    );
  }

  function value_call(
    bytes[] memory state,
    bytes32 command,
    bytes32 indices
  ) internal returns (bool success, bytes memory outdata) {
    uint256 calleth;
    bytes memory v = state[uint8(bytes1(indices))];
    require(v.length == 32, "_execute: value call has no value indicated.");
    assembly {
      calleth := mload(add(v, 0x20))
    }
    (success, outdata) = address(uint160(uint256(command))).call{ // target
      value: calleth
    }(
      state.buildInputs(
        //selector
        bytes4(command),
        bytes32(uint256(indices << 8) | CommandBuilder.IDX_END_OF_ARGS)
      )
    );
  }
}

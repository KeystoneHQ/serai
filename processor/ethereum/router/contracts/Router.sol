// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

import "IERC20.sol";

import "Schnorr.sol";

import "IRouter.sol";

/*
  The Router directly performs low-level calls in order to fine-tune the gas settings. Since this
  contract is meant to relay an entire batch of transactions, the ability to exactly meter
  individual transactions is critical.

  We don't check the return values as we don't care if the calls succeeded. We solely care we made
  them. If someone configures an external contract in a way which borks, we epxlicitly define that
  as their fault and out-of-scope to this contract.

  If an actual invariant within Serai exists, an escape hatch exists to move to a new contract. Any
  improperly handled actions can be re-signed and re-executed at that point in time.
*/
// slither-disable-start low-level-calls,unchecked-lowlevel

/// @title Serai Router
/// @author Luke Parker <lukeparker@serai.exchange>
/// @notice Intakes coins for the Serai network and handles relaying batches of transfers out
contract Router is IRouterWithoutCollisions {
  /**
   * @dev The next nonce used to determine the address of contracts deployed with CREATE. This is
   *   used to predict the addresses of deployed contracts ahead of time.
   */
  /*
    We don't expose a getter for this as it shouldn't be expected to have any specific value at a
    given moment in time. If someone wants to know the address of their deployed contract, they can
    have it emit an event and verify the emitting contract is the expected one.
  */
  uint256 private _smartContractNonce;

  /**
   * @dev The nonce to verify the next signature with, incremented upon an action to prevent
   *   replays/out-of-order execution
   */
  uint256 private _nextNonce;

  /**
   * @dev The current public key for Serai's Ethereum validator set, in the form the Schnorr library
   *   expects
   */
  bytes32 private _seraiKey;

  /// @dev The address escaped to
  address private _escapedTo;

  /// @dev Updates the Serai key. This does not update `_nextNonce`
  /// @param nonceUpdatedWith The nonce used to update the key
  /// @param newSeraiKey The key updated to
  function _updateSeraiKey(uint256 nonceUpdatedWith, bytes32 newSeraiKey) private {
    _seraiKey = newSeraiKey;
    emit SeraiKeyUpdated(nonceUpdatedWith, newSeraiKey);
  }

  /// @notice The constructor for the relayer
  /// @param initialSeraiKey The initial key for Serai's Ethereum validators
  constructor(bytes32 initialSeraiKey) {
    // Nonces are incremented by 1 upon account creation, prior to any code execution, per EIP-161
    // This is incompatible with any networks which don't have their nonces start at 0
    _smartContractNonce = 1;

    // Set the Serai key
    _updateSeraiKey(0, initialSeraiKey);

    // We just consumed nonce 0 when setting the initial Serai key
    _nextNonce = 1;

    // We haven't escaped to any address yet
    _escapedTo = address(0);
  }

  /**
   * @dev
   *   Verify a signature of the calldata, placed immediately after the function selector. The
   *   calldata should be signed with the nonce taking the place of the signature's commitment to
   *   its nonce, and the signature solution zeroed.
   */
  function verifySignature()
    private
    returns (uint256 nonceUsed, bytes memory message, bytes32 messageHash)
  {
    // If the escape hatch was triggered, reject further signatures
    if (_escapedTo != address(0)) {
      revert EscapeHatchInvoked();
    }

    message = msg.data;
    uint256 messageLen = message.length;
    /*
      function selector, signature

      This check means we don't read memory, and as we attempt to clear portions, write past it
      (triggering undefined behavior).
    */
    if (messageLen < 68) {
      revert InvalidSignature();
    }

    // Read _nextNonce into memory as the nonce we'll use
    nonceUsed = _nextNonce;

    // Declare memory to copy the signature out to
    bytes32 signatureC;
    bytes32 signatureS;

    // slither-disable-next-line assembly
    assembly {
      // Read the signature (placed after the function signature)
      signatureC := mload(add(message, 36))
      signatureS := mload(add(message, 68))

      // Overwrite the signature challenge with the nonce
      mstore(add(message, 36), nonceUsed)
      // Overwrite the signature response with 0
      mstore(add(message, 68), 0)

      // Calculate the message hash
      messageHash := keccak256(add(message, 32), messageLen)
    }

    // Verify the signature
    if (!Schnorr.verify(_seraiKey, messageHash, signatureC, signatureS)) {
      revert InvalidSignature();
    }

    // Set the next nonce
    unchecked {
      _nextNonce = nonceUsed + 1;
    }

    /*
      Advance the message past the function selector, enabling decoding the arguments. Ideally, we'd
      also advance past the signature (to simplify decoding arguments and save some memory). This
      would transfrom message from:

        message (pointer)
               v
               ------------------------------------------------------------
               | 32-byte length | 4-byte selector | Signature | Arguments |
               ------------------------------------------------------------

      to:

                 message (pointer)
                        v
        ----------------------------------------------
        | Junk 68 bytes | 32-byte length | Arguments |
        ----------------------------------------------

      Unfortunately, doing so corrupts the offsets defined within the ABI itself. We settle for a
      transform to:

                message (pointer)
                       v
        ---------------------------------------------------------
        | Junk 4 bytes | 32-byte length | Signature | Arguments |
        ---------------------------------------------------------
    */
    // slither-disable-next-line assembly
    assembly {
      message := add(message, 4)
      mstore(message, sub(messageLen, 4))
    }
  }

  /// @notice Update the key representing Serai's Ethereum validators
  /**
   * @dev This assumes the key is correct. No checks on it are performed.
   *
   *  The hex bytes are to cause a collision with `IRouter.updateSeraiKey`.
   */
  // @param signature The signature by the current key authorizing this update
  // @param newSeraiKey The key to update to
  function updateSeraiKey5A8542A2() external {
    (uint256 nonceUsed, bytes memory args,) = verifySignature();
    /*
      We could replace this with a length check (if we don't simply assume the calldata is valid as
      it was properly signed) + mload to save 24 gas but it's not worth the complexity.
    */
    (,, bytes32 newSeraiKey) = abi.decode(args, (bytes32, bytes32, bytes32));
    _updateSeraiKey(nonceUsed, newSeraiKey);
  }

  /// @notice Transfer coins into Serai with an instruction
  /// @param coin The coin to transfer in (address(0) if Ether)
  /// @param amount The amount to transfer in (msg.value if Ether)
  /**
   * @param instruction The Shorthand-encoded InInstruction for Serai to associate with this
   *   transfer in
   */
  // Re-entrancy doesn't bork this function
  // slither-disable-next-line reentrancy-events
  function inInstruction(address coin, uint256 amount, bytes memory instruction) external payable {
    // Check the transfer
    if (coin == address(0)) {
      if (amount != msg.value) revert AmountMismatchesMsgValue();
    } else {
      (bool success, bytes memory res) = address(coin).call(
        abi.encodeWithSelector(IERC20.transferFrom.selector, msg.sender, address(this), amount)
      );

      /*
        Require there was nothing returned, which is done by some non-standard tokens, or that the
        ERC20 contract did in fact return true
      */
      bool nonStandardResOrTrue = (res.length == 0) || abi.decode(res, (bool));
      if (!(success && nonStandardResOrTrue)) revert TransferFromFailed();
    }

    /*
      Due to fee-on-transfer tokens, emitting the amount directly is frowned upon. The amount
      instructed to be transferred may not actually be the amount transferred.

      If we add nonReentrant to every single function which can effect the balance, we can check the
      amount exactly matches. This prevents transfers of less value than expected occurring, at
      least, not without an additional transfer to top up the difference (which isn't routed through
      this contract and accordingly isn't trying to artificially create events from this contract).

      If we don't add nonReentrant, a transfer can be started, and then a new transfer for the
      difference can follow it up (again and again until a rounding error is reached). This contract
      would believe all transfers were done in full, despite each only being done in part (except
      for the last one).

      Given fee-on-transfer tokens aren't intended to be supported, the only token actively planned
      to be supported is Dai and it doesn't have any fee-on-transfer logic, and how fee-on-transfer
      tokens aren't even able to be supported at this time by the larger Serai network, we simply
      classify this entire class of tokens as non-standard implementations which induce undefined
      behavior.

      It is the Serai network's role not to add support for any non-standard implementations.
    */
    emit InInstruction(msg.sender, coin, amount, instruction);
  }

  /// @dev Perform an ERC20 transfer out
  /// @param to The address to transfer the coins to
  /// @param coin The coin to transfer
  /// @param amount The amount of the coin to transfer
  function erc20TransferOut(address to, address coin, uint256 amount) private {
    /*
      The ERC20s integrated are presumed to have a constant gas cost, meaning this can only be
      insufficient:

        A) An integrated ERC20 uses more gas than this limit (presumed not to be the case)
        B) An integrated ERC20 is upgraded (integrated ERC20s are presumed to not be upgradeable)
        C) This has a variable gas cost and the user set a hook on receive which caused this (in
           which case, we accept dropping this)
        D) The user was blacklisted (in which case, we again accept dropping this)
        E) Other extreme edge cases, for which such tokens are assumed to not be integrated
        F) Ethereum opcodes are repriced in a sufficiently breaking fashion

      This should be in such excess of the gas requirements of integrated tokens we'll survive
      repricing, so long as the repricing doesn't revolutionize EVM gas costs as we know it. In such
      a case, Serai would have to migrate to a new smart contract using `escapeHatch`.
    */
    uint256 _gas = 100_000;

    bytes memory _calldata = abi.encodeWithSelector(IERC20.transfer.selector, to, amount);
    bool _success;
    // slither-disable-next-line assembly
    assembly {
      /*
        `coin` is trusted so we can accept the risk of a return bomb here, yet we won't check the
        return value anyways so there's no need to spend the gas decoding it. We assume failures
        are the fault of the recipient, not us, the sender. We don't want to have such errors block
        the queue of transfers to make.

        If there ever was some invariant broken, off-chain actions is presumed to occur to move to a
        new smart contract with whatever necessary changes made/response occurring.
      */
      _success :=
        call(
          _gas,
          coin,
          // Ether value
          0,
          // calldata
          add(_calldata, 0x20),
          mload(_calldata),
          // return data
          0,
          0
        )
    }
  }

  /// @dev Perform an ETH/ERC20 transfer out
  /// @param to The address to transfer the coins to
  /// @param coin The coin to transfer (address(0) if Ether)
  /// @param amount The amount of the coin to transfer
  function transferOut(address to, address coin, uint256 amount) private {
    if (coin == address(0)) {
      // Enough gas to service the transfer and a minimal amount of logic
      uint256 _gas = 5_000;
      // This uses assembly to prevent return bombs
      bool _success;
      // slither-disable-next-line assembly
      assembly {
        _success :=
          call(
            _gas,
            to,
            amount,
            // calldata
            0,
            0,
            // return data
            0,
            0
          )
      }
    } else {
      erc20TransferOut(to, coin, amount);
    }
  }

  /// @notice Execute some arbitrary code within a secure sandbox
  /**
   * @dev This performs sandboxing by deploying this code with `CREATE`. This is an external
   *   function as we can't meter `CREATE`/internal functions. We work around this by calling this
   *   function with `CALL` (which we can meter). This does forward `msg.value` to the newly
   *  deployed contract.
   */
  /// @param code The code to execute
  function executeArbitraryCode(bytes memory code) external payable {
    // Because we're creating a contract, increment our nonce
    _smartContractNonce += 1;

    uint256 msgValue = msg.value;
    address contractAddress;
    // We need to use assembly here because Solidity doesn't expose CREATE
    // slither-disable-next-line assembly
    assembly {
      contractAddress := create(msgValue, add(code, 0x20), mload(code))
    }
  }

  /// @notice Execute a batch of `OutInstruction`s
  /**
   * @dev All `OutInstruction`s in a batch are only for a single coin to simplify handling of the
   *  fee.
   *
   *  The hex bytes are to cause a function selector collision with `IRouter.execute`.
   */
  // @param signature The signature by the current key for Serai's Ethereum validators
  // @param coin The coin all of these `OutInstruction`s are for
  // @param fee The fee to pay (in coin) to the caller for their relaying of this batch
  // @param outs The `OutInstruction`s to act on
  // Each individual call is explicitly metered to ensure there isn't a DoS here
  // slither-disable-next-line calls-loop
  function execute4DE42904() external {
    (uint256 nonceUsed, bytes memory args, bytes32 message) = verifySignature();
    (,, address coin, uint256 fee, IRouter.OutInstruction[] memory outs) =
      abi.decode(args, (bytes32, bytes32, address, uint256, IRouter.OutInstruction[]));

    // TODO: Also include a bit mask here
    emit Executed(nonceUsed, message);

    /*
      Since we don't have a re-entrancy guard, it is possible for instructions from later batches to
      be executed before these instructions. This is deemed fine. We only require later batches be
      relayed after earlier batches in order to form backpressure. This means if a batch has a fee
      which isn't worth relaying the batch for, so long as later batches are sufficiently
      worthwhile, every batch will be relayed.
    */

    // slither-disable-next-line reentrancy-events
    for (uint256 i = 0; i < outs.length; i++) {
      // If the destination is an address, we perform a direct transfer
      if (outs[i].destinationType == IRouter.DestinationType.Address) {
        /*
          This may cause a revert  if the destination isn't actually a valid address. Serai is
          trusted to not pass a malformed destination, yet if it ever did, it could simply re-sign a
          corrected batch using this nonce.
        */
        address destination = abi.decode(outs[i].destination, (address));
        transferOut(destination, coin, outs[i].amount);
      } else {
        // Prepare the transfer
        uint256 ethValue = 0;
        if (coin == address(0)) {
          // If it's ETH, we transfer the amount with the call
          ethValue = outs[i].amount;
        } else {
          /*
            If it's an ERC20, we calculate the address of the will-be contract and transfer to it
            before deployment. This avoids needing to deploy the contract, then call transfer, then
            call the contract again
          */
          address nextAddress = address(
            uint160(uint256(keccak256(abi.encodePacked(address(this), _smartContractNonce))))
          );
          erc20TransferOut(nextAddress, coin, outs[i].amount);
        }

        (IRouter.CodeDestination memory destination) =
          abi.decode(outs[i].destination, (IRouter.CodeDestination));

        /*
          Perform the deployment with the defined gas budget.

          We don't care if the following call fails as we don't want to block/retry if it does.
          Failures are considered the recipient's fault. We explicitly do not want the surface
          area/inefficiency of caching these for later attempted retires.

          We don't have to worry about a return bomb here as this is our own function which doesn't
          return any data.
        */
        address(this).call{ gas: destination.gasLimit, value: ethValue }(
          abi.encodeWithSelector(Router.executeArbitraryCode.selector, destination.code)
        );
      }
    }

    // Transfer the fee to the relayer
    transferOut(msg.sender, coin, fee);
  }

  /// @notice Escapes to a new smart contract
  /**
   * @dev This should be used upon an invariant being reached or new functionality being needed.
   *
   * The hex bytes are to cause a collision with `IRouter.escapeHatch`.
   */
  // @param signature The signature by the current key for Serai's Ethereum validators
  // @param escapeTo The address to escape to
  function escapeHatchDCDD91CC() external {
    // Verify the signature
    (, bytes memory args,) = verifySignature();

    (,, address escapeTo) = abi.decode(args, (bytes32, bytes32, address));

    if (escapeTo == address(0)) {
      revert InvalidEscapeAddress();
    }
    /*
      We want to define the escape hatch so coins here now, and latently received, can be forwarded.
      If the last Serai key set could update the escape hatch, they could siphon off latently
      received coins without penalty (if they update the escape hatch after unstaking).
    */
    if (_escapedTo != address(0)) {
      revert EscapeHatchInvoked();
    }

    _escapedTo = escapeTo;
    emit EscapeHatch(escapeTo);
  }

  /// @notice Escape coins after the escape hatch has been invoked
  /// @param coin The coin to escape
  function escape(address coin) external {
    if (_escapedTo == address(0)) {
      revert EscapeHatchNotInvoked();
    }

    emit Escaped(coin);

    // Fetch the amount to escape
    uint256 amount = address(this).balance;
    if (coin != address(0)) {
      amount = IERC20(coin).balanceOf(address(this));
    }

    // Perform the transfer
    transferOut(_escapedTo, coin, amount);
  }

  /// @notice Fetch the next nonce to use by an action published to this contract
  /// return The next nonce to use by an action published to this contract
  function nextNonce() external view returns (uint256) {
    return _nextNonce;
  }

  /// @notice Fetch the current key for Serai's Ethereum validator set
  /// @return The current key for Serai's Ethereum validator set
  function seraiKey() external view returns (bytes32) {
    return _seraiKey;
  }

  /// @notice Fetch the address escaped to
  /// @return The address which was escaped to (address(0) if the escape hatch hasn't been invoked)
  function escapedTo() external view returns (address) {
    return _escapedTo;
  }
}

// slither-disable-end low-level-calls,unchecked-lowlevel

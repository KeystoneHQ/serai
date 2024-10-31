// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

// TODO: MIT licensed interface

import "IERC20.sol";

import "Schnorr.sol";

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
contract Router {
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

  /// @title The type of destination
  /// @dev A destination is either an address or a blob of code to deploy and call
  enum DestinationType {
    Address,
    Code
  }

  /// @title A code destination
  /**
   * @dev If transferring an ERC20 to this destination, it will be transferred to the address the
   *   code will be deployed to. If transferring ETH, it will be transferred with the deployment of
   *   the code. `code` is deployed with CREATE (calling its constructor). The entire deployment
   *   (and associated sandboxing) must consume less than `gasLimit` units of gas or it will revert.
   */
  struct CodeDestination {
    uint32 gasLimit;
    bytes code;
  }

  /// @title An instruction to transfer coins out
  /// @dev Specifies a destination and amount but not the coin as that's assumed to be contextual
  struct OutInstruction {
    DestinationType destinationType;
    bytes destination;
    uint256 amount;
  }

  /// @title A signature
  /// @dev Thin wrapper around `c, s` to simplify the API
  struct Signature {
    bytes32 c;
    bytes32 s;
  }

  /// @notice Emitted when the key for Serai's Ethereum validators is updated
  /// @param nonce The nonce consumed to update this key
  /// @param key The key updated to
  event SeraiKeyUpdated(uint256 indexed nonce, bytes32 indexed key);

  /// @notice Emitted when an InInstruction occurs
  /// @param from The address which called `inInstruction` and caused this event to be emitted
  /// @param coin The coin transferred in
  /// @param amount The amount of the coin transferred in
  /// @param instruction The Shorthand-encoded InInstruction for Serai to decode and handle
  event InInstruction(
    address indexed from, address indexed coin, uint256 amount, bytes instruction
  );

  /// @notice Emitted when a batch of `OutInstruction`s occurs
  /// @param nonce The nonce consumed to execute this batch of transactions
  /// @param messageHash The hash of the message signed for the executed batch
  event Executed(uint256 indexed nonce, bytes32 indexed messageHash);

  /// @notice Emitted when `escapeHatch` is invoked
  /// @param escapeTo The address to escape to
  event EscapeHatch(address indexed escapeTo);

  /// @notice Emitted when coins escape through the escape hatch
  /// @param coin The coin which escaped
  event Escaped(address indexed coin);

  /// @notice The contract has had its escape hatch invoked and won't accept further actions
  error EscapeHatchInvoked();
  /// @notice The signature was invalid
  error InvalidSignature();
  /// @notice The amount specified didn't match `msg.value`
  error AmountMismatchesMsgValue();
  /// @notice The call to an ERC20's `transferFrom` failed
  error TransferFromFailed();

  /// @notice An invalid address to escape to was specified.
  error InvalidEscapeAddress();
  /// @notice Escaping when escape hatch wasn't invoked.
  error EscapeHatchNotInvoked();

  /**
   * @dev Updates the Serai key at the end of the current function. Executing at the end of the
   *   current function allows verifying a signature with the current key. This does not update
   *   `_nextNonce`
   */
  /// @param nonceUpdatedWith The nonce used to update the key
  /// @param newSeraiKey The key updated to
  modifier updateSeraiKeyAtEndOfFn(uint256 nonceUpdatedWith, bytes32 newSeraiKey) {
    // Run the function itself
    _;

    // Update the key
    _seraiKey = newSeraiKey;
    emit SeraiKeyUpdated(nonceUpdatedWith, newSeraiKey);
  }

  /// @notice The constructor for the relayer
  /// @param initialSeraiKey The initial key for Serai's Ethereum validators
  constructor(bytes32 initialSeraiKey) updateSeraiKeyAtEndOfFn(0, initialSeraiKey) {
    // Nonces are incremented by 1 upon account creation, prior to any code execution, per EIP-161
    // This is incompatible with any networks which don't have their nonces start at 0
    _smartContractNonce = 1;

    // We consumed nonce 0 when setting the initial Serai key
    _nextNonce = 1;

    // We haven't escaped to any address yet
    _escapedTo = address(0);
  }

  /// @dev Verify a signature
  /// @param message The message to pass to the Schnorr contract
  /// @param signature The signature by the current key for this message
  function verifySignature(bytes32 message, Signature calldata signature) private {
    // If the escape hatch was triggered, reject further signatures
    if (_escapedTo != address(0)) {
      revert EscapeHatchInvoked();
    }
    // Verify the signature
    if (!Schnorr.verify(_seraiKey, message, signature.c, signature.s)) {
      revert InvalidSignature();
    }
    // Set the next nonce
    unchecked {
      _nextNonce++;
    }
  }

  /// @notice Update the key representing Serai's Ethereum validators
  /// @dev This assumes the key is correct. No checks on it are performed
  /// @param newSeraiKey The key to update to
  /// @param signature The signature by the current key authorizing this update
  function updateSeraiKey(bytes32 newSeraiKey, Signature calldata signature)
    external
    updateSeraiKeyAtEndOfFn(_nextNonce, newSeraiKey)
  {
    /*
      This DST needs a length prefix as well to prevent DSTs potentially being substrings of each
      other, yet this is fine for our well-defined, extremely-limited use.

      We don't encode the chain ID as Serai generates independent keys for each integration. If
      Ethereum L2s are integrated, and they reuse the Ethereum validator set, we would use the
      existing Serai key yet we'd apply an off-chain derivation scheme to bind it to specific
      networks. This also lets Serai identify EVMs per however it wants, solving the edge case where
      two instances of the EVM share a chain ID for whatever horrific reason.

      This uses encodePacked as all items present here are of fixed length.
    */
    bytes32 message = keccak256(abi.encodePacked("updateSeraiKey", _nextNonce, newSeraiKey));
    verifySignature(message, signature);
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
   *  fee
   */
  /// @param coin The coin all of these `OutInstruction`s are for
  /// @param fee The fee to pay (in coin) to the caller for their relaying of this batch
  /// @param outs The `OutInstruction`s to act on
  /// @param signature The signature by the current key for Serai's Ethereum validators
  // Each individual call is explicitly metered to ensure there isn't a DoS here
  // slither-disable-next-line calls-loop
  function execute(
    address coin,
    uint256 fee,
    OutInstruction[] calldata outs,
    Signature calldata signature
  ) external {
    // Verify the signature
    // This uses `encode`, not `encodePacked`, as `outs` is of variable length
    // TODO: Use a custom encode in verifySignature here with assembly (benchmarking before/after)
    bytes32 message = keccak256(abi.encode("execute", _nextNonce, coin, fee, outs));
    verifySignature(message, signature);

    // TODO: Also include a bit mask here
    emit Executed(_nextNonce, message);

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
      if (outs[i].destinationType == DestinationType.Address) {
        /*
          This may cause a revert if the destination isn't actually a valid address. Serai is
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

        (CodeDestination memory destination) = abi.decode(outs[i].destination, (CodeDestination));

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
  /// @dev This should be used upon an invariant being reached or new functionality being needed
  /// @param escapeTo The address to escape to
  /// @param signature The signature by the current key for Serai's Ethereum validators
  function escapeHatch(address escapeTo, Signature calldata signature) external {
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

    // Verify the signature
    bytes32 message = keccak256(abi.encodePacked("escapeHatch", _nextNonce, escapeTo));
    verifySignature(message, signature);

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

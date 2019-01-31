pragma solidity ^0.5.0;
contract Proxy2 {
    address public mastercopy;
    
    constructor(address _mastercopy, address paymentToken, uint256 payment) public {
        require(_mastercopy != address(0), "Invalid master copy address provided");
        mastercopy = _mastercopy;
        if (payment > 0) {
            if (paymentToken == address(0)) {
                 // solium-disable-next-line security/no-tx-origin
                require(tx.origin.send(payment), "Could not pay safe creation with ether");
            } else {
                 // solium-disable-next-line security/no-tx-origin
                require(transferToken(paymentToken, tx.origin, payment), "Could not pay safe creation with token");
            }
        } 
    }
    
    /// @dev Transfers a token and returns if it was a success
    /// @param token Token that should be transferred
    /// @param receiver Receiver to whom the token should be transferred
    /// @param amount The amount of tokens that should be transferred
    function transferToken (
        address token, 
        address receiver,
        uint256 amount
    )
        internal
        returns (bool transferred)
    {
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", receiver, amount);
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let success := call(sub(gas, 10000), token, 0, add(data, 0x20), mload(data), 0, 0)
            let ptr := mload(0x40)
            returndatacopy(ptr, 0, returndatasize)
            switch returndatasize 
            case 0 { transferred := success }
            case 0x20 { transferred := iszero(or(iszero(success), iszero(mload(ptr)))) }
            default { transferred := 0 }
        }
    }

    /// @dev Fallback function forwards all transactions and returns all received return data.
    function ()
        external
        payable
    {
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let masterCopy := and(sload(0), 0xffffffffffffffffffffffffffffffffffffffff)
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas, masterCopy, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if eq(success, 0) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}

/// @title Proxy Factory - Allows to create new proxy contact and execute a message call to the new proxy within one transaction using create2
/// @author Richard Meissner - <richard@gnosis.pm>
contract ProxyFactory2 {

    event ProxyCreated(address proxy);

    function proxyCreationCode() public view returns (bytes memory) {
        return type(Proxy2).creationCode;
    }

    function proxyRuntimeCode() public view returns (bytes memory) {
        return type(Proxy2).runtimeCode;
    }

    /// @dev Allows to create new proxy contact and execute a message call to the new proxy within one transaction.
    /// @param _mastercopy Address of master copy.
    /// @param initializer Payload for message call sent to new proxy contract.
    function createProxy(address _mastercopy, bytes memory initializer, address paymentToken, uint256 payment, uint256 nonce)
        public
        returns (Proxy2 proxy)
    {
        bytes32 salt = keccak256(abi.encodePacked(initializer, nonce));
        bytes memory deploymentData = abi.encodePacked(type(Proxy2).creationCode, uint256(_mastercopy), uint256(paymentToken), payment);
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            proxy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), salt)
        }
        if (initializer.length > 0)
            // solium-disable-next-line security/no-inline-assembly
            assembly {
                if eq(call(gas, proxy, 0, add(initializer, 0x20), mload(initializer), 0, 0), 0) { revert(0,0) }
            }
        emit ProxyCreated(address(proxy));
    }
}

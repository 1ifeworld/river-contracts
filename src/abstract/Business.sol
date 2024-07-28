// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Trust} from "./Trust.sol";

abstract contract Business is Trust {

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    ERRORS                      *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */      

    /// @dev Revert when contract not set to public OR when target account does not have sufficient allowance 
    error Not_Allowed();
    /// @dev Revert when trying to withdraw more than ETH balance in contract
    error Insufficent_Eth_Balance();
    /// @dev Revert when passing incorrect msg value
    error Msg_Value_Incorrect();
    /// @dev Revert if ETH transfer fails
    error Eth_Transfer_Failed();      

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    EVENTS                      *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */       

    /**
     * @dev Emit an event when payoutRecipient variable is adjusted
     *
     * @param payoutRecipient Address of payout recipient
     */        
    event SetPayoutRecipient(address payoutRecipient);

    /**
     * @dev Emit an event when price variable is adjusted
     *
     * @param price New price value
     */    
    event SetPrice(uint256 price);

    /**
     * @dev Emit an event when owner initiates transfer to payoutRecipient
     *
     * @param to     Address of recipient
     * @param amount The amount of ether withdrawn
     */
    event Withdraw(address indexed to, uint256 amount);    

    /**
     * @dev Emit an event when account allowance is adjusted
     *
     * @param to     Address of recipient
     * @param newAllowance New allowance
     */    
    event Allowance(address indexed to, uint256 newAllowance);    

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    STORAGE                     *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */      

    /**
     * @dev Gas limit with signficant buffer prevents undefined gas limit DDOS
     *      while being high enough to ensure sends succeed even with complex recipients
     */
    uint256 internal constant SAFE_GAS_LIMIT = 1_500_000;     

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    STORAGE                     *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */       

    /**
     * @dev Price required to send alongside `register` or `registerFor` calls
     * @dev Adjustable by trusted callers
     */
    uint256 public price;    

    /**
     * @dev Where ETH is transferred when `withdraw` is called
     * @dev Adjustable by trusted callers
     */
    address public payoutRecipient;        

    /**
     * @dev Variable for setting open/closed access to `register` and `registerFor` calls
     */
    bool public isPublic;

    /**
     * @dev Mapping that provides granular permissioning for accounts to register rids
     * @dev Adjustable by trusted callers
     */
    mapping(address account => uint256 allowance) public allowanceOf;

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *            MODIFER + CONSTRUCTOR               *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */       

    /**
     * @notice Requires function to be called with specific msg.value
     */
    modifier paid() {
        if (msg.value != price) revert Msg_Value_Incorrect();
        _;
    }

    /**
     * @notice Set the initial owner, price, and payout recipient
     *
     * @param _initialOwner     Address of the contract owner.
     * @param _payoutRecipient  Address of the payout recipient.
     * @param _price            Initial cost of `paid` functions.
     */
    constructor(address _initialOwner, address _payoutRecipient, uint256 _price) Trust(_initialOwner) {
        _unsafeSetPayoutRecipient(_payoutRecipient);
        _unsafeSetPrice(_price);
    }

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *              PUBLIC + ALLOWANCE                *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */    

    /**
     * @notice Function to flip public access to `register` and `registerFor` functions
     */
    function toggleIsPublic() onlyTrusted external returns (bool status) {
        status = isPublic = !isPublic;
    }

    /**
     * @notice Allows trustedCaller to increase accounts allowance to register rids
     */
    function increaseAllowance(address account, uint256 increase) onlyTrusted external returns (uint256 newAllowance) {
        newAllowance = allowanceOf[account] += increase;
        emit Allowance(account, newAllowance);
    }

    /**
     * @notice Allows trustedCaller to clear accounts allowance to register rids
     */
    function clearAllowance(address account) onlyTrusted external {
        // Delete sets value to 0, which is then emitted as `newAllowance`
        delete allowanceOf[account];
        emit Allowance(account, 0);
    }

    /**
     * @notice Decreases account allowance by one. 
     * @dev No checks on internal function, enforce elsewhere.
     */    
    function _unsafeDecreaseAllowance(address account) internal {
        uint256 newAllowance = --allowanceOf[account];
        emit Allowance(account, newAllowance);
    }             

    /**
     * @notice External getter to view account `isAllowed` status
     */
    function isAllowed(address account) external view returns (bool status) {
        status = isPublic || allowanceOf[account] != 0 ? true : false;
    }    

    /**
     * @notice Internal helper for viewing account `isAllowed` status
     */
    function _isAllowed(address account) internal view {
        if (!isPublic) {
            if (allowanceOf[account] == 0) revert Not_Allowed();
        }        
    }        

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    PAYOUTS                     *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */

    /**
     * @notice Updates payout recipient
     */   
    function setPayoutRecipient(address _payoutRecipient) onlyTrusted external {
        _unsafeSetPayoutRecipient(_payoutRecipient);
    }

    /**
     * @notice Internal helper
     */   
    function _unsafeSetPayoutRecipient(address _payoutRecipient) internal {
        if (_payoutRecipient == address(0)) revert Cannot_Set_Zero_Address();
        payoutRecipient = _payoutRecipient;
        emit SetPayoutRecipient(payoutRecipient);
    }

    /**
     * @notice Updates price for `register` and `registerFor` functions
     */   
    function setPrice(uint256 _price) onlyTrusted external {
        _unsafeSetPrice(_price);
    }    

    /**
     * @notice Internal helper
     */   
    function _unsafeSetPrice(uint256 _price) internal {
        price = _price;
        emit SetPrice(price);
    }     

    /**
     * @notice Sends specified ETH balance of contract to recipient address
     */   
    function withdraw(uint256 amount) onlyOwner public {
        if (amount > address(this).balance) revert Insufficent_Eth_Balance();
        (bool success, ) = payoutRecipient.call{value: amount, gas: SAFE_GAS_LIMIT}("");
        if (!success) revert Eth_Transfer_Failed();
        emit Withdraw(payoutRecipient, amount);
    }

    /**
     * @dev Allows contract to receive ETH
     */   
    receive() external payable {}
}
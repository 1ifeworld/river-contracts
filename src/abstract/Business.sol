// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Trust} from "./Trust.sol";

abstract contract Business is Trust {

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    EVENTS                      *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */       

    event SetPayoutRecipient(address payoutRecipientRecipient);
    event SetPrice(uint256 price);

    /**
     * @dev Emit an event when owner initiates transfer to payoutRecipient
     *
     * @param to     Address of recipient
     * @param amount The amount of ether withdrawn
     */
    event Withdraw(address indexed to, uint256 amount);    
    event Allowance(address indexed to, uint256 newAllowance);    

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    ERRORS                      *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */      

    error Not_Allowed();
    error Insufficient_Balance();
    error Msg_Value_Incorrect();
    error Eth_Transfer_Failed();    
    error Cannot_Set_Zero_Address();    

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    STORAGE                     *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */       

    uint256 public price;    
    address public payoutRecipient;        
    bool public isPublic;
    mapping(address account => uint256 allowance) public allowanceOf;

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *            MODIFER + CONSTRUCTOR               *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */       

    modifier paid() {
        if (msg.value != price) revert Msg_Value_Incorrect();
        _;
    }

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

    function toggleIsPublic() onlyTrusted external returns (bool status) {
        status = isPublic = !isPublic;
    }

    function isAllowed(address account) onlyTrusted external view returns (bool status) {
        status = isPublic || allowanceOf[account] != 0 ? true : false;
    }    

    function _isAllowed(address account) internal view {
        if (!isPublic) {
            if (allowanceOf[account] == 0) revert Not_Allowed();
        }        
    }    

    function increaseAllowance(address account, uint256 increase) onlyTrusted external returns (uint256 newAllowance) {
        newAllowance = allowanceOf[account] += increase;
        emit Allowance(account, newAllowance);
    }

    function clearAllowance(address account) onlyTrusted external {
        // Delete sets value to 0, which is then emitted as `newAllowance`
        delete allowanceOf[account];
        emit Allowance(account, 0);
    }

    // @dev can be called by anyone. enforce checks elsewhere
    function _unsafeDecreaseAllowance(address account) internal {
        uint256 newAllowance = --allowanceOf[account];
        emit Allowance(account, newAllowance);
    }             

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    PAYOUTS                     *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */

    function setPayoutRecipient(address _payoutRecipient) onlyTrusted external {
        _unsafeSetPayoutRecipient(_payoutRecipient);
    }

    function _unsafeSetPayoutRecipient(address _payoutRecipient) internal {
        if (_payoutRecipient == address(0)) revert Cannot_Set_Zero_Address();
        payoutRecipient = payoutRecipient;
        emit SetPayoutRecipient(payoutRecipient);
    }

    function setPrice(uint256 _price) onlyTrusted external {
        _unsafeSetPrice(_price);
    }    

    function _unsafeSetPrice(uint256 _price) internal {
        price = _price;
        emit SetPrice(price);
    }     

    function withdraw(uint256 amount) onlyOwner public {
        if (amount > address(this).balance) revert Insufficient_Balance();
        (bool success, ) = payoutRecipient.call{value: amount}("");
        if (!success) revert Eth_Transfer_Failed();
        emit Withdraw(payoutRecipient, amount);
    }

    receive() external payable {}
}
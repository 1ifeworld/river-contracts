// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IPostGateway} from "./interfaces/IPostGateway.sol";

/**
 * @title PostGateway
 * @author Lifeworld
 */
contract PostGateway is IPostGateway {

    ////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////    

    string public constant NAME = "Post Gateway";

    string public constant VERSION = "2024.02.05";

    ////////////////////////////////////////////////////////////////
    // EVENTS
    ////////////////////////////////////////////////////////////////    

    /**
     * @dev Emit an event when a new post has been broadcasted
     *
     * @param sender    Address of the calling account
     */
    event NewPost(address indexed sender);    

    ////////////////////////////////////////////////////////////////
    // POST
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Broadcasts post for indexing
     */
    function post(Post calldata /*post*/) external {
        emit NewPost(msg.sender);
    }    

    /**
     * @notice Broadcasts posts for indexing
     */
    function postBatch(Post[] calldata posts) external {
        address sender = msg.sender;
        for (uint256 i; i < posts.length; ++i) {
            emit NewPost(sender);
        }        
    }          

    ////////////////////////////////////////////////////////////////
    // TYPE EXPORT
    ////////////////////////////////////////////////////////////////

    function exportPostStruct() external pure returns (Post memory post) {
        return post;
    }    

    function exportMessageStruct() external pure returns (Message memory message) {
        return message;
    }    

    function exportChannelStruct() external pure returns (Channel memory channel) {
        return channel;
    }

    function exportItemStruct() external pure returns (Item memory item) {
        return item;
    }    

    function exportAddItemStruct() external pure returns (AddItem memory addItem) {
        return addItem;
    }    

    function exportRemoveItemStruct() external pure returns (RemoveItem memory removeItem) {
        return removeItem;
    }     
}
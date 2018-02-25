pragma solidity ^0.4.19;

/*
Author: Chance Santana-Wees
Contact Email: figs999@gmail.com
*/

import './zeppelin/ownership/CanReclaimToken.sol';
import './zeppelin/token/ERC20/StandardToken.sol';

contract Kr8Base {
    address packer;
    
    modifier onlyFromValidator() {
        require(msg.sender == address(packer));
        _;
    }

    function StoreValidatedKr8(address msgSender, uint blockNumber, bytes32 derivedHash, bytes32 parentHash, bytes32[8] logsBloom, address miner) public onlyFromValidator returns (uint8 success);
}

contract Kr8Packer is Ownable {
    address kr8;
    
    modifier ownerOnly() {
        require(msg.sender == owner);
        _;
    }
    
    function SetKr8Base(Kr8Base kr8Base) public ownerOnly {
        kr8 = kr8Base;
    }
    
    function PackKr8(address msgSender, bytes rlpData) public returns (uint8);
}

contract Kr8 is StandardToken, CanReclaimToken, Kr8Base {
    //string public name = "Kr8.io";
    //string public symbol = "KR8";
    
    uint PACKING_REWARD = 100;
    
    mapping(uint => bytes32) public blockNumberToHash;
    mapping(uint => address) public blockNumberToMiner;
    mapping(uint => bytes32[8])   private blockNumberToLogsBloom;
    
    function Kr8() public {
        owner = msg.sender;
        balances[owner] = 1000000000;
    }
    
    modifier ownerOnly() {
        require(msg.sender == owner);
        _;
    }
    
    modifier costsKr8(uint blockNumber) {
        require(blockNumberToMiner[blockNumber] != 0);
        require(balances[msg.sender] > 0 );
        balances[msg.sender]--;
        _;
    }
    
    function SetKr8Packer(Kr8Packer kr8Packer) public ownerOnly {
        packer = kr8Packer;
    }
     
    function SetPackingReward(uint reward) public ownerOnly {
        PACKING_REWARD = reward;
    }
    
    function BlockHash(uint blockNumber) public view returns (bytes32 blockHash) {
        blockHash = block.blockhash(blockNumber);
        if(blockHash == 0)
            blockHash = blockNumberToHash[blockNumber];
    }
    
    event Kr8Packed(uint indexed blockChunk, uint blockNumber);
    
    function PackKr8(bytes rlpData) public {
        Kr8Packer kr8Packer = Kr8Packer(packer);
        
        uint kr8sPacked = kr8Packer.PackKr8(msg.sender, rlpData);
        
        if(kr8sPacked > 0)
            balances[msg.sender] = SafeMath.add( balances[msg.sender], PACKING_REWARD);
    }
    
    function GetLogBloom(uint blockNumber) public costsKr8(blockNumber) returns (bytes32[8]) {
        return blockNumberToLogsBloom[blockNumber];
    }
    
    bytes32 constant eventTopic = keccak256(keccak256("DataStored(bytes,bytes)"));
    
    event DataStored(bytes indexed _data, bytes data);
    
    function Kr8_Store(bytes dataBlob) public {
        DataStored(dataBlob, dataBlob);
    }
    
    function ValidateOracLogStorage(uint blockNumber, bytes data) public returns (bool valid){
        bytes32 _topic1 = keccak256(address(this));
        bytes32 _topic2 = eventTopic;
        bytes32 _topic3 = keccak256(keccak256(data));
        
        return ValidateLogPresenseByTopics3(blockNumber, _topic1, _topic2, _topic3);
    }
    
    function ValidateLogPresenseByTopics3(uint blockNumber, bytes32 _topic1, bytes32 _topic2, bytes32 _topic3) public returns (bool valid) {
        bytes32[8] memory logsBloom = GetLogBloom(blockNumber);
        
        bool foundInLogs = true;
        
        for(uint b = 0; b < 8; b++) {
            bytes32 bloom = 0;
            for(uint i = 0; i < 6; i += 2) {
                assembly {
                    if eq(mod(byte(i, _topic1),8), b) {
                        bloom := or(bloom, exp(2,byte(add(1,i), _topic1)))
                    }
                    if eq(mod(byte(i, _topic2),8), b) {
                        bloom := or(bloom, exp(2,byte(add(1,i), _topic2)))
                    }
                    if eq(mod(byte(i, _topic3),8), b) {
                        bloom := or(bloom, exp(2,byte(add(1,i), _topic3)))
                    }
                }
            }
            
            assembly {
                if gt(bloom, 0) {
                    let bloomAnd := and(mload(add(logsBloom,mul(0x20,sub(7,b)))),bloom)
                    let equal := eq(bloomAnd,bloom)
                    
                    if eq(equal,0) {
                        b := 8
                        foundInLogs := 0
                    }
                }
            }
        }
        
        valid = foundInLogs;
    }
    
    function StoreValidatedKr8(address msgSender, uint blockNumber, bytes32 derivedHash, bytes32 parentHash, bytes32[8] logsBloom, address miner) public onlyFromValidator returns (uint8 success) {
        success = 0;
        
        if((msgSender == owner || blockNumberToMiner[blockNumber] == 0))
        {
            //assert(derivedHash == BlockHash(blockNumber));
            
            if(blockNumberToHash[blockNumber] == 0)
                blockNumberToHash[blockNumber] = derivedHash;
            
            blockNumberToHash[blockNumber-1] = parentHash;
            blockNumberToLogsBloom[blockNumber] = logsBloom;
            blockNumberToMiner[blockNumber] = miner;
            
            Kr8Packed(blockNumber/100, blockNumber);
            success = 1;
        }
    }
}

contract Kr8Packer_1 is Kr8Packer {
    function PackKr8(address msgSender, bytes rlpData) public returns (uint8) {
        require(msg.sender == kr8);
        
        bytes32 parentHash;
        address miner;
        bytes32 derivedHash;
        uint blockNumber;
        
        bytes32[8] memory logsBloom;
        
        uint offset;
        
        assembly {
            offset := add(32, rlpData)
        }
        
        uint8 kr8sPacked = 0;
        
        Kr8Base kr8Base = Kr8Base(kr8);
        
        while(offset < rlpData.length)
        {
            uint nextOffset;
            
            assembly {
                //determine _size of next RLP encoded header which begins at offset
                let _idx := sub(offset,31)
                //_size is now length of the RLPs length2 token.
                let _size := sub(and(mload(_idx),0xFF),0xF7)
                let size_idx := add(_idx,_size)
                
                //_size+2 is the index of the first chunk of real data in the loaded RLP bytes, used later
                _idx := add(offset,add(_size,2))
                
                let returnJump := postMask1
                let mask := 0xFFFF
                jumpi(calcMask, gt(_size, 2))
                
            postMask1:
                //size of RLP = (size of length1 token [1]) + (size of length2 token [_size]) + (value encoded by length2 token)
                _size := add(add(and(mload(size_idx),mask),_size),1)
                nextOffset := add(offset,_size)
                
                //calculate hash of RLP encoded header
                derivedHash := keccak256(offset, _size)
                
                //parentHash is the first chunk of real data, which we stored as _idx above.
                parentHash := mload(_idx)
                //skip to index of miner address
                _idx := add(_idx, 54)
                miner := and(mload(_idx),0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
                //skip to index of logs bloom...
                //it's a fixed size array so we're just setting it's pointer address to the index of the bloom already in memory
                logsBloom := add(_idx, 133)
                
                
                //next we need a length token, 1 byte after the log bloom.
                _idx := add(logsBloom, 226)
                //we skip past one variably sized value, so we need to know it's length
                _size := sub(and(mload(_idx), 0xFF), 128)
                
                //next is another size token, we need to increment one additional byte past the _size
                _idx := add(add(_idx, _size),1)
                _size := sub(and(mload(_idx), 0xFF), 128)
            
                mask := 0xFFFF
                returnJump := postMask2
                jumpi(calcMask, gt(_size, 2))

            postMask2:
                blockNumber := and(mload(add(_idx, _size)), mask)
                jump(end)
                
            calcMask:
                switch _size
                case 3 { mask := 0xFFFFFF }
                case 4 { mask := 0xFFFFFFFF }
                case 5 { mask := 0xFFFFFFFFFF }
                case 6 { mask := 0xFFFFFFFFFFFF }
                case 7 { mask := 0xFFFFFFFFFFFFFF }
                case 8 { mask := 0xFFFFFFFFFFFFFFFF }
                jump(returnJump)
            
            end:
            }
            
            require(nextOffset > offset && blockNumber > 0);
            offset = nextOffset;
            
            kr8sPacked += kr8Base.StoreValidatedKr8(msgSender, blockNumber, derivedHash,  parentHash, logsBloom, miner);
        }
        
        return 1;
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {NamepassBasename} from "../src/NamepassBasename.sol";

// Mock controller for testing
contract MockController {
    struct RegisterRequest {
        string name;
        address owner;
        uint256 duration;
        address resolver;
        bytes[] data;
        bool reverseRecord;
    }
    
    bool public shouldRevert = false;
    string public lastRequestName;
    address public lastRequestOwner;
    uint256 public lastRequestDuration;
    address public lastRequestResolver;
    bool public lastRequestReverseRecord;
    uint256 public lastValue;
    
    function register(RegisterRequest calldata request) external payable {
        require(!shouldRevert, "Mock registration failed");
        lastRequestName = request.name;
        lastRequestOwner = request.owner;
        lastRequestDuration = request.duration;
        lastRequestResolver = request.resolver;
        lastRequestReverseRecord = request.reverseRecord;
        lastValue = msg.value;
    }
    
    function registerPrice(string calldata, uint256) external pure returns (uint256) {
        return 0.001 ether;
    }
    
    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }
}

contract NamepassBasenameTest is Test {
    NamepassBasename public namepassBasename;
    MockController public mockController;
    address public owner = address(this);
    address public user = address(0x123);

    // Allow contract to receive ETH
    receive() external payable {}

    function setUp() public {
        mockController = new MockController();
        namepassBasename = new NamepassBasename(address(mockController));
        
        // Give test accounts some ETH
        vm.deal(owner, 100 ether);
        vm.deal(user, 100 ether);
    }

    // === VOUCHER CREATION TESTS ===
    
    function test_CreateVoucher_Length3() public {
        bytes32 secretHash = keccak256("test_secret_3");
        uint8 length = 3;
        uint256 expectedEscrow = 0.1 ether;
        uint256 expectedFee = 0.0004 ether;
        uint256 totalRequired = expectedEscrow + expectedFee;
        
        vm.expectEmit(true, false, false, true);
        emit NamepassBasename.VoucherCreated(secretHash, length, expectedEscrow, block.timestamp + 365 days);
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        assertEq(uint256(namepassBasename.getVoucherStatus(secretHash)), uint256(NamepassBasename.VoucherStatus.Available));
        
        (bytes32 hash, uint8 len, uint256 escrow, uint256 expiry, bool used) = namepassBasename.vouchers(secretHash);
        assertEq(hash, secretHash);
        assertEq(len, length);
        assertEq(escrow, expectedEscrow);
        assertEq(expiry, block.timestamp + 365 days);
        assertFalse(used);
    }
    
    function test_CreateVoucher_Length4() public {
        bytes32 secretHash = keccak256("test_secret_4");
        uint8 length = 4;
        uint256 expectedEscrow = 0.01 ether;
        uint256 expectedFee = 0.0002 ether;
        uint256 totalRequired = expectedEscrow + expectedFee;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        (, , uint256 escrow, , ) = namepassBasename.vouchers(secretHash);
        assertEq(escrow, expectedEscrow);
    }
    
    function test_CreateVoucher_Length5to9() public {
        bytes32 secretHash = keccak256("test_secret_5");
        uint8 length = 7;
        uint256 expectedEscrow = 0.001 ether;
        uint256 expectedFee = 0.0001 ether;
        uint256 totalRequired = expectedEscrow + expectedFee;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        (, , uint256 escrow, , ) = namepassBasename.vouchers(secretHash);
        assertEq(escrow, expectedEscrow);
    }
    
    function test_CreateVoucher_Length10Plus() public {
        bytes32 secretHash = keccak256("test_secret_10");
        uint8 length = 15;
        uint256 expectedEscrow = 0.0001 ether;
        uint256 expectedFee = 0.00005 ether;
        uint256 totalRequired = expectedEscrow + expectedFee;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        (, , uint256 escrow, , ) = namepassBasename.vouchers(secretHash);
        assertEq(escrow, expectedEscrow);
    }
    
    function test_CreateVoucher_RevertTooShort() public {
        bytes32 secretHash = keccak256("test_secret_short");
        uint8 length = 2;
        
        vm.expectRevert("Basename too short");
        namepassBasename.createVoucher{value: 1 ether}(secretHash, length);
    }
    
    function test_CreateVoucher_RevertAlreadyExists() public {
        bytes32 secretHash = keccak256("test_secret_duplicate");
        uint8 length = 5;
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        vm.expectRevert("Voucher already exists");
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
    }
    
    function test_CreateVoucher_RevertInsufficientETH() public {
        bytes32 secretHash = keccak256("test_secret_insufficient");
        uint8 length = 5;
        uint256 insufficient = 0.0005 ether; // Less than required
        
        vm.expectRevert("Insufficient ETH sent");
        namepassBasename.createVoucher{value: insufficient}(secretHash, length);
    }
    
    function test_CreateVoucher_OnlyOwner() public {
        bytes32 secretHash = keccak256("test_secret_owner");
        uint8 length = 5;
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        vm.prank(user);
        vm.expectRevert();
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
    }

    // === VOUCHER REDEMPTION TESTS ===
    
    function test_RedeemVoucher_Success() public {
        // Create voucher first
        bytes32 secret = keccak256("redemption_secret");
        bytes32 secretHash = keccak256(abi.encodePacked(secret));
        uint8 length = 5;
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        // Redeem voucher
        string memory label = "hello";
        
        vm.expectEmit(true, false, true, true);
        emit NamepassBasename.VoucherRedeemed(secretHash, label, user);
        
        vm.prank(user);
        namepassBasename.redeem(label, secret);
        
        // Check voucher is now used
        assertEq(uint256(namepassBasename.getVoucherStatus(secretHash)), uint256(NamepassBasename.VoucherStatus.Used));
        
        // Check controller received correct call
        assertEq(mockController.lastRequestName(), label);
        assertEq(mockController.lastRequestOwner(), user);
        assertEq(mockController.lastRequestDuration(), 365 days);
        assertEq(mockController.lastValue(), 0.001 ether);
    }
    
    function test_RedeemVoucher_RevertNonExistent() public {
        bytes32 secret = keccak256("nonexistent_secret");
        string memory label = "hello";
        
        vm.prank(user);
        vm.expectRevert("Voucher does not exist");
        namepassBasename.redeem(label, secret);
    }
    
    function test_RedeemVoucher_RevertAlreadyUsed() public {
        // Create and redeem voucher
        bytes32 secret = keccak256("used_secret");
        bytes32 secretHash = keccak256(abi.encodePacked(secret));
        uint8 length = 5;
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        vm.prank(user);
        namepassBasename.redeem("hello", secret);
        
        // Try to redeem again
        vm.prank(user);
        vm.expectRevert("Voucher already used");
        namepassBasename.redeem("hello", secret);
    }
    
    function test_RedeemVoucher_RevertExpired() public {
        // Create voucher
        bytes32 secret = keccak256("expired_secret");
        bytes32 secretHash = keccak256(abi.encodePacked(secret));
        uint8 length = 5;
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        // Fast forward past expiry
        vm.warp(block.timestamp + 366 days);
        
        vm.prank(user);
        vm.expectRevert("Voucher expired");
        namepassBasename.redeem("hello", secret);
    }
    
    function test_RedeemVoucher_RevertWrongLength() public {
        // Create voucher for length 5
        bytes32 secret = keccak256("length_secret");
        bytes32 secretHash = keccak256(abi.encodePacked(secret));
        uint8 length = 5;
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        // Try to redeem with wrong length
        vm.prank(user);
        vm.expectRevert("Wrong length for this voucher");
        namepassBasename.redeem("hi", secret); // length 2, not 5
    }

    // === VOUCHER STATUS TESTS ===
    
    function test_GetVoucherStatus_Invalid() public {
        bytes32 nonExistentHash = keccak256("nonexistent");
        assertEq(uint256(namepassBasename.getVoucherStatus(nonExistentHash)), uint256(NamepassBasename.VoucherStatus.Invalid));
    }
    
    function test_GetVoucherStatus_Available() public {
        bytes32 secretHash = keccak256("available_secret");
        uint8 length = 5;
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        assertEq(uint256(namepassBasename.getVoucherStatus(secretHash)), uint256(NamepassBasename.VoucherStatus.Available));
    }
    
    function test_GetVoucherStatus_Used() public {
        bytes32 secret = keccak256("used_status_secret");
        bytes32 secretHash = keccak256(abi.encodePacked(secret));
        uint8 length = 5;
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        vm.prank(user);
        namepassBasename.redeem("hello", secret);
        
        assertEq(uint256(namepassBasename.getVoucherStatus(secretHash)), uint256(NamepassBasename.VoucherStatus.Used));
    }
    
    function test_GetVoucherStatus_Expired() public {
        bytes32 secretHash = keccak256("expired_status_secret");
        uint8 length = 5;
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        vm.warp(block.timestamp + 366 days);
        
        assertEq(uint256(namepassBasename.getVoucherStatus(secretHash)), uint256(NamepassBasename.VoucherStatus.Expired));
    }

    // === WITHDRAW TESTS ===
    
    function test_Withdraw_Success() public {
        // Create some vouchers to add funds to contract
        bytes32 secretHash1 = keccak256("withdraw_secret_1");
        bytes32 secretHash2 = keccak256("withdraw_secret_2");
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash1, 5);
        namepassBasename.createVoucher{value: totalRequired}(secretHash2, 6);
        
        uint256 contractBalance = address(namepassBasename).balance;
        uint256 ownerBalanceBefore = owner.balance;
        
        namepassBasename.withdraw(payable(owner));
        
        assertEq(address(namepassBasename).balance, 0);
        assertEq(owner.balance, ownerBalanceBefore + contractBalance);
    }
    
    function test_Withdraw_OnlyOwner() public {
        vm.prank(user);
        vm.expectRevert();
        namepassBasename.withdraw(payable(user));
    }

    // === INTEGRATION TESTS ===
    
    function test_FullVoucherLifecycle() public {
        bytes32 secret = keccak256("lifecycle_secret");
        bytes32 secretHash = keccak256(abi.encodePacked(secret));
        uint8 length = 5;
        uint256 totalRequired = 0.001 ether + 0.0001 ether;
        
        // 1. Create voucher
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        assertEq(uint256(namepassBasename.getVoucherStatus(secretHash)), uint256(NamepassBasename.VoucherStatus.Available));
        
        // 2. Redeem voucher
        vm.prank(user);
        namepassBasename.redeem("hello", secret);
        assertEq(uint256(namepassBasename.getVoucherStatus(secretHash)), uint256(NamepassBasename.VoucherStatus.Used));
        
        // 3. Verify controller interaction
        assertEq(mockController.lastRequestName(), "hello");
        assertEq(mockController.lastRequestOwner(), user);
    }

    // === FUZZ TESTS ===
    
    function testFuzz_CreateVoucher_ValidLengths(uint8 length, bytes32 secretHash) public {
        vm.assume(length >= 3 && length <= 255);
        vm.assume(secretHash != 0);
        
        uint256 expectedEscrow;
        if (length == 3) expectedEscrow = 0.1 ether;
        else if (length == 4) expectedEscrow = 0.01 ether;
        else if (length >= 5 && length <= 9) expectedEscrow = 0.001 ether;
        else expectedEscrow = 0.0001 ether;
        
        uint256 totalRequired = namepassBasename._calculateFinalValue(expectedEscrow);
        
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        assertEq(uint256(namepassBasename.getVoucherStatus(secretHash)), uint256(NamepassBasename.VoucherStatus.Available));
        
        (bytes32 hash, uint8 len, uint256 escrow, , bool used) = namepassBasename.vouchers(secretHash);
        assertEq(hash, secretHash);
        assertEq(len, length);
        assertEq(escrow, expectedEscrow);
        assertFalse(used);
    }
    
    function testFuzz_CreateVoucher_RevertInvalidLength(uint8 length, bytes32 secretHash) public {
        vm.assume(length < 3);
        vm.assume(secretHash != 0);
        
        vm.expectRevert("Basename too short");
        namepassBasename.createVoucher{value: 1 ether}(secretHash, length);
    }
    
    function testFuzz_RedeemVoucher_ValidLabels(string memory label, bytes32 secret) public {
        vm.assume(bytes(label).length >= 3 && bytes(label).length <= 20);
        vm.assume(secret != 0);
        
        bytes32 secretHash = keccak256(abi.encodePacked(secret));
        uint8 length = uint8(bytes(label).length);
        
        uint256 expectedEscrow;
        if (length == 3) expectedEscrow = 0.1 ether;
        else if (length == 4) expectedEscrow = 0.01 ether;
        else if (length >= 5 && length <= 9) expectedEscrow = 0.001 ether;
        else expectedEscrow = 0.0001 ether;
        
        uint256 totalRequired = namepassBasename._calculateFinalValue(expectedEscrow);
        
        // Create voucher
        namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
        
        // Redeem voucher
        vm.prank(user);
        namepassBasename.redeem(label, secret);
        
        // Verify redemption
        assertEq(uint256(namepassBasename.getVoucherStatus(secretHash)), uint256(NamepassBasename.VoucherStatus.Used));
        assertEq(mockController.lastRequestName(), label);
        assertEq(mockController.lastRequestOwner(), user);
    }
    
    function testFuzz_CalculateFinalValue_Properties(uint256 escrowAmount) public {
        // Bound escrow amount to reasonable values (at least 0.00001 ETH)
        escrowAmount = bound(escrowAmount, 10000000000000, 10 ether);
        
        uint256 finalValue = namepassBasename._calculateFinalValue(escrowAmount);
        
        // Final value should always be greater than original
        assertGt(finalValue, escrowAmount);
        
        // Fee should be reasonable for bounded inputs
        uint256 fee = finalValue - escrowAmount;
        
        // For the predefined tiers, fee should be reasonable
        if (escrowAmount == 0.1 ether || escrowAmount == 0.01 ether || 
            escrowAmount == 0.001 ether || escrowAmount == 0.0001 ether) {
            assertLe(fee, escrowAmount); // Fee <= 100% for predefined tiers
        } else {
            // For fallback fee, just ensure it's the expected amount
            assertEq(fee, 20000000000000); // 0.00002 ETH
        }
    }
}

// === INVARIANT TESTS ===
contract NamepassBasenameInvariantTest is Test {
    NamepassBasename public namepassBasename;
    MockController public mockController;
    
    // Handler contract for invariant testing
    VoucherHandler public handler;
    
    function setUp() public {
        mockController = new MockController();
        namepassBasename = new NamepassBasename(address(mockController));
        handler = new VoucherHandler(namepassBasename);
        
        // Set handler as target for invariant testing
        targetContract(address(handler));
        
        // Fund handler
        vm.deal(address(handler), 1000 ether);
    }
    
    // Invariant: Contract balance should equal sum of unused voucher escrows plus fees
    function invariant_BalanceEqualsEscrows() public {
        uint256 totalEscrows = handler.getTotalUnusedEscrows();
        uint256 contractBalance = address(namepassBasename).balance;
        
        // Contract balance should be at least the sum of unused escrows
        assertGe(contractBalance, totalEscrows);
    }
    
    // Invariant: Used vouchers should never become available again
    function invariant_UsedVouchersStayUsed() public {
        bytes32[] memory usedVouchers = handler.getUsedVouchers();
        
        for (uint256 i = 0; i < usedVouchers.length; i++) {
            NamepassBasename.VoucherStatus status = namepassBasename.getVoucherStatus(usedVouchers[i]);
            assertTrue(status == NamepassBasename.VoucherStatus.Used || 
                      status == NamepassBasename.VoucherStatus.Expired);
        }
    }
    
    // Invariant: Voucher count should never decrease
    function invariant_VoucherCountNeverDecreases() public {
        uint256 currentCount = handler.getTotalVoucherCount();
        uint256 previousCount = handler.getPreviousVoucherCount();
        
        assertGe(currentCount, previousCount);
        handler.updatePreviousCount();
    }
}

// Handler contract for invariant testing
contract VoucherHandler is Test {
    NamepassBasename public namepassBasename;
    
    bytes32[] public createdVouchers;
    bytes32[] public usedVouchers;
    uint256 public previousVoucherCount;
    
    constructor(NamepassBasename _namepassBasename) {
        namepassBasename = _namepassBasename;
    }
    
    receive() external payable {}
    
    function createVoucher(bytes32 secretHash, uint8 length) public {
        length = uint8(bound(length, 3, 20));
        
        // Skip if voucher already exists
        if (namepassBasename.getVoucherStatus(secretHash) != NamepassBasename.VoucherStatus.Invalid) {
            return;
        }
        
        uint256 expectedEscrow;
        if (length == 3) expectedEscrow = 0.1 ether;
        else if (length == 4) expectedEscrow = 0.01 ether;
        else if (length >= 5 && length <= 9) expectedEscrow = 0.001 ether;
        else expectedEscrow = 0.0001 ether;
        
        uint256 totalRequired = namepassBasename._calculateFinalValue(expectedEscrow);
        
        if (address(this).balance >= totalRequired) {
            namepassBasename.createVoucher{value: totalRequired}(secretHash, length);
            createdVouchers.push(secretHash);
        }
    }
    
    function redeemVoucher(bytes32 secret, string memory label) public {
        bytes32 secretHash = keccak256(abi.encodePacked(secret));
        
        if (namepassBasename.getVoucherStatus(secretHash) == NamepassBasename.VoucherStatus.Available) {
            try namepassBasename.redeem(label, secret) {
                usedVouchers.push(secretHash);
            } catch {
                // Redemption failed, continue
            }
        }
    }
    
    function getTotalUnusedEscrows() public view returns (uint256 total) {
        for (uint256 i = 0; i < createdVouchers.length; i++) {
            if (namepassBasename.getVoucherStatus(createdVouchers[i]) == NamepassBasename.VoucherStatus.Available) {
                (, , uint256 escrow, , ) = namepassBasename.vouchers(createdVouchers[i]);
                total += escrow;
            }
        }
    }
    
    function getUsedVouchers() public view returns (bytes32[] memory) {
        return usedVouchers;
    }
    
    function getTotalVoucherCount() public view returns (uint256) {
        return createdVouchers.length;
    }
    
    function getPreviousVoucherCount() public view returns (uint256) {
        return previousVoucherCount;
    }
    
    function updatePreviousCount() public {
        previousVoucherCount = createdVouchers.length;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IBaseRegistrarController {
    struct RegisterRequest {
        string name;
        address owner;
        uint256 duration;
        address resolver;
        bytes[] data;
        bool reverseRecord;
    }

    function register(RegisterRequest calldata request) external payable;
    function registerPrice(string calldata name, uint256 duration) external view returns (uint256);
}

contract NamepassBasename is Ownable {

    IBaseRegistrarController public controller;

    constructor(address controllerAddr) Ownable(msg.sender) {
        controller = IBaseRegistrarController(controllerAddr);
    }

    // Voucher representation
    struct Voucher {
        bytes32 secretHash;   // keccak256(secret)
        uint8 length;         // length of basename allowed
        uint256 escrow;       // ETH escrowed for registration
        uint256 expiry;       // block.timestamp + 365 days
        bool used;            // one-time redeemable
    }

    mapping(bytes32 => Voucher) public vouchers;

    // Voucher Status Enum
    enum VoucherStatus { Invalid, Available, Used, Expired }

    event VoucherCreated(bytes32 indexed secretHash, uint8 length, uint256 escrow, uint256 expiry);
    event VoucherRedeemed(bytes32 indexed secretHash, string label, address indexed redeemer);

    // === ESCROW FEE LOGIC ===
    uint256 private constant POINT_ONE_ETH = 100000000000000000;      // 0.1
    uint256 private constant POINT_ZERO_ONE_ETH = 10000000000000000;  // 0.01
    uint256 private constant POINT_ZERO_ZERO_ONE_ETH = 1000000000000000;  // 0.001
    uint256 private constant POINT_ZERO_ZERO_ZERO_ONE_ETH = 100000000000000; // 0.0001

    // Flat fees
    uint256 private constant FEE_FOR_POINT_ONE = 400000000000000;                // 0.4% of 0.1 ETH = 0.0004 ETH
    uint256 private constant FEE_FOR_POINT_ZERO_ONE = 200000000000000;           // 2% of 0.01 ETH = 0.0002 ETH
    uint256 private constant FEE_FOR_POINT_ZERO_ZERO_ONE = 100000000000000;      // 10% of 0.001 ETH = 0.0001 ETH
    uint256 private constant FEE_FOR_POINT_ZERO_ZERO_ZERO_ONE = 50000000000000;  // 50% of 0.0001 ETH = 0.00005 ETH
    uint256 private constant FALLBACK_FEE = 20000000000000;                      // Fallback fee of 0.00002 ETH

    function _calculateFinalValue(uint256 originalValue) public pure returns (uint256) {
        if (originalValue == POINT_ONE_ETH) return originalValue + FEE_FOR_POINT_ONE;
        if (originalValue == POINT_ZERO_ONE_ETH) return originalValue + FEE_FOR_POINT_ZERO_ONE;
        if (originalValue == POINT_ZERO_ZERO_ONE_ETH) return originalValue + FEE_FOR_POINT_ZERO_ZERO_ONE;
        if (originalValue == POINT_ZERO_ZERO_ZERO_ONE_ETH) return originalValue + FEE_FOR_POINT_ZERO_ZERO_ZERO_ONE;
        return originalValue + FALLBACK_FEE;
    }

    // === VOUCHER CREATION ===
    function createVoucher(bytes32 secretHash, uint8 length) external payable onlyOwner {
        require(length >= 3, "Basename too short");
        require(vouchers[secretHash].secretHash == 0, "Voucher already exists");

        uint256 escrow;
        if (length == 3) escrow = POINT_ONE_ETH;
        else if (length == 4) escrow = POINT_ZERO_ONE_ETH;
        else if (length >= 5 && length <= 9) escrow = POINT_ZERO_ZERO_ONE_ETH;
        else escrow = POINT_ZERO_ZERO_ZERO_ONE_ETH;

        uint256 finalValue = _calculateFinalValue(escrow);
        require(msg.value >= finalValue, "Insufficient ETH sent");

        vouchers[secretHash] = Voucher({
            secretHash: secretHash,
            length: length,
            escrow: escrow,
            expiry: block.timestamp + 365 days,
            used: false
        });

        emit VoucherCreated(secretHash, length, escrow, block.timestamp + 365 days);
    }

    // === REDEEM VOUCHER ===
    function redeem(string calldata label, bytes32 secret) external {
        bytes32 hash = keccak256(abi.encodePacked(secret));
        Voucher storage v = vouchers[hash];

        require(v.secretHash != 0, "Voucher does not exist");
        require(!v.used, "Voucher already used");
        require(block.timestamp <= v.expiry, "Voucher expired");
        require(bytes(label).length == v.length, "Wrong length for this voucher");

        // Build request
        IBaseRegistrarController.RegisterRequest memory req =
            IBaseRegistrarController.RegisterRequest({
                name: label,
                owner: msg.sender,
                duration: 365 days,
                resolver: address(0),
                data: new bytes[](0),
                reverseRecord: false
            });

        v.used = true;

        controller.register{value: v.escrow}(req);

        emit VoucherRedeemed(hash, label, msg.sender);
    }

    // === VOUCHER STATUS ===
    function getVoucherStatus(bytes32 secretHash) external view returns (VoucherStatus) {
        Voucher memory v = vouchers[secretHash];
        if (v.secretHash == 0) return VoucherStatus.Invalid;
        if (v.used) return VoucherStatus.Used;
        if (block.timestamp > v.expiry) return VoucherStatus.Expired;
        return VoucherStatus.Available;
    }

    // === OWNER WITHDRAW ===
    function withdraw(address payable to) external onlyOwner {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "Withdraw failed");
    }
}

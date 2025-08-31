# Base Sepolia Testnet Setup Guide

## 1. Get Base Sepolia ETH (Free!)

### Option A: Base Sepolia Faucet
- Visit: https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet
- Connect your wallet
- Request testnet ETH (usually 0.05 ETH per day)

### Option B: Sepolia ETH Bridge
- Get Sepolia ETH from: https://sepoliafaucet.com/
- Bridge to Base Sepolia using: https://bridge.base.org/

## 2. Add Base Sepolia to MetaMask

**Network Details:**
- Network Name: Base Sepolia
- RPC URL: https://sepolia.base.org
- Chain ID: 84532
- Currency Symbol: ETH
- Block Explorer: https://sepolia.basescan.org

## 3. Deploy Your Contract

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Add your private key to `.env`:
```
PRIVATE_KEY=0x...your_private_key
```

3. Deploy to Base Sepolia:
```bash
forge script script/NamepassBasename.s.sol --rpc-url base_sepolia --broadcast --verify
```

## 4. Find the Basename Controller Address

The script currently uses a placeholder address. To find the real Base Sepolia Basename controller:

1. Check Base docs: https://docs.base.org/
2. Look for Basename contracts on Base Sepolia
3. Update the controller address in the deployment script

## 5. Test Your Contract

Once deployed, you can:
- Create vouchers using the contract owner account
- Test redemption with different basename lengths
- Verify gas costs are reasonable on testnet

## 6. Basename Testing

Base Sepolia supports Basenames for testing:
- Register test basenames at: https://www.base.org/names (testnet version)
- Use your deployed contract to create vouchers
- Test the full voucher → redemption flow

## Security Notes

- Never use your mainnet private key for testnet
- Create a separate wallet for testnet development
- Testnet ETH has no value - perfect for testing!

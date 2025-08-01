
# Data Creation 

```ts
script
├── buildEmailProofs.ts
├── computeGuardianAddress.ts
├── data
│   ├── addresses.json
│   ├── EmailProofs.json
│   ├── emails.json
│   ├── guardians_addrs.json
│   └── guardians_salt.json
├── extractPublicKeyHash.ts
├── helpers
│   └── generateAccountCode.ts
├── proofs
│   ├── produceProofs.ts
│   ├── produceProofs2.ts
│   └── proveGuardian.ts
└── utils
    ├── types.ts
    └── UniversalEmailRecoveryModule.ts
```

### Install
```bash
npm i
```

### Build EmailProof Params (output: Wrote → ./script/data/EmailProofs.json):
```bash
npx tsx script/buildEmailProofs.ts 
```

### Get DKIM hash:
```bash
npx tsx script/extractPublicKeyHash.ts <.eml file path>
# npx tsx script/extractPublicKeyHash.ts emails/unknown_197f8f95f49748e1.eml  
```

### Compute Guardian Address (output: Wrote → ./script/data/guardians_addrs.json):
```bash
npx tsx script/computeGuardianAddress.ts 
```

# Solidity
```ts
src
└── Account.sol

test
├── AccountTest.t.sol
├── Base.t.sol
├── Helpers.sol
├── libs
│   ├── CommandUtils.sol
│   ├── DecimalUtils.sol
│   └── StringUtils.sol
└── Structs.sol
```
// Simple test script for debugging Hedera array storage
const { ethers } = require('hardhat');

async function main() {
  console.log('🚀 Deploying AdminTest contract...');
  
  // Deploy the test contract
  const AdminTest = await ethers.getContractFactory('AdminTest');
  const adminTest = await AdminTest.deploy();
  await adminTest.waitForDeployment();
  
  const contractAddress = await adminTest.getAddress();
  console.log('✅ AdminTest deployed to:', contractAddress);
  
  // Get the deployer (owner)
  const [deployer] = await ethers.getSigners();
  console.log('👤 Deployer address:', deployer.address);
  
  // Test issuer address
  const testIssuer = '0x1234567890123456789012345678901234567890';
  
  console.log('\n📊 Initial state check:');
  const initialState = await adminTest.debugStorage();
  console.log('Array length:', initialState.arrayLength.toString());
  console.log('Counter:', initialState.counter.toString());
  
  console.log('\n➕ Adding test issuer:', testIssuer);
  
  try {
    // Add issuer with proper gas settings for Hedera
    const tx = await adminTest.addIssuer(testIssuer, {
      gasLimit: 500000,  // High gas limit for Hedera
      gasPrice: ethers.parseUnits('100', 'gwei')  // High gas price for Hedera
    });
    
    console.log('Transaction hash:', tx.hash);
    console.log('Waiting for confirmation...');
    
    const receipt = await tx.wait();
    console.log('✅ Transaction confirmed in block:', receipt.blockNumber);
    console.log('Gas used:', receipt.gasUsed.toString());
    
    // Check all events
    console.log('\n📋 Events emitted:');
    receipt.logs.forEach((log, index) => {
      try {
        const parsed = adminTest.interface.parseLog(log);
        console.log(`Event ${index}:`, parsed.name, parsed.args);
      } catch (e) {
        console.log(`Event ${index}: Could not parse`);
      }
    });
    
  } catch (error) {
    console.error('❌ Transaction failed:', error);
    return;
  }
  
  console.log('\n📊 Post-transaction state check:');
  
  // Check final state
  const finalState = await adminTest.debugStorage();
  console.log('Array length:', finalState.arrayLength.toString());
  console.log('Counter:', finalState.counter.toString());
  console.log('First issuer:', finalState.firstIssuer);
  console.log('First issuer active:', finalState.firstIssuerActive);
  
  // Check mapping directly
  const isIssuerCheck = await adminTest.isIssuer(testIssuer);
  console.log('isIssuer mapping check:', isIssuerCheck);
  
  // Check array directly
  const arrayLength = await adminTest.getIssuerCount();
  console.log('getIssuerCount():', arrayLength.toString());
  
  if (arrayLength > 0) {
    const firstInArray = await adminTest.issuers(0);
    console.log('issuers[0]:', firstInArray);
  }
  
  // Get all issuers
  const allIssuers = await adminTest.getAllIssuers();
  console.log('getAllIssuers():', allIssuers);
  
  console.log('\n🎯 Summary:');
  console.log('- Contract deployed successfully');
  console.log('- Transaction executed successfully');
  console.log('- Final array length:', finalState.arrayLength.toString());
  console.log('- Mapping works:', isIssuerCheck);
  
  if (finalState.arrayLength > 0) {
    console.log('✅ SUCCESS: Array storage is working on Hedera!');
  } else {
    console.log('❌ ISSUE: Array is still empty after successful transaction');
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

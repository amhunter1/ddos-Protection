const { DDoSProtection, createDDoSProtection } = require('./src/middleware/ddosProtection');

// Test configuration validation
console.log('Testing DDoS Protection System...\n');

// Test 1: Valid configuration 
try {
  const protection = new DDoSProtection({
    maxRequestsPerMinute: 100,
    logLevel: 'info'
  });
  console.log('✅ Valid configuration accepted');
} catch (error) {
  console.log('❌ Valid configuration rejected:', error.message);
}

// Test 2: Invalid configuration
try {
  const protection = new DDoSProtection({
    maxRequestsPerMinute: 'invalid',
    logLevel: 'invalid'
  });
  console.log('❌ Invalid configuration should have been rejected');
} catch (error) {
  console.log('✅ Invalid configuration properly rejected:', error.message);
}

// Test 3: Middleware creation
try {
  const middleware = createDDoSProtection({
    maxRequestsPerMinute: 50
  });
  console.log('✅ Middleware creation successful');
} catch (error) {
  console.log('❌ Middleware creation failed:', error.message);
}

// Test 4: Statistics
try {
  const protection = new DDoSProtection({
    maxRequestsPerMinute: 100
  });
  setTimeout(async () => {
    const stats = await protection.getStats();
    console.log('✅ Statistics retrieval successful:', stats);

    // Close connection
    await protection.close();
    console.log('✅ Connection closed successfully');
  }, 1000);
} catch (error) {
  console.log('❌ Statistics test failed:', error.message);
}
console.log('\nTest completed!');

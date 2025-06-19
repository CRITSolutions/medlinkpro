const bcrypt = require('bcryptjs');

async function generateHash() {
    const password = 'Admin123!';
    const saltRounds = 12;
    
    console.log('🔑 Generating bcrypt hash for password:', password);
    console.log('🧂 Salt rounds:', saltRounds);
    
    try {
        const hash = await bcrypt.hash(password, saltRounds);
        console.log('✅ Generated hash:', hash);
        
        const isValid = await bcrypt.compare(password, hash);
        console.log('🧪 Hash validation test:', isValid ? '✅ PASS' : '❌ FAIL');
        
        console.log('\n📝 SQL to update all demo users:');
        console.log(`UPDATE users SET password_hash = '${hash}' WHERE email LIKE '%@medlinkpro.demo';`);
        
    } catch (error) {
        console.error('❌ Error generating hash:', error);
    }
}

generateHash();
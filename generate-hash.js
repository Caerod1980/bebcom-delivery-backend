const bcrypt = require('bcrypt');

async function generateHash() {
    const saltRounds = 12;
    const plainPassword = 'Bebcom25*'; // <-- ALTERE PARA SUA SENHA REAL!
    
    try {
        console.log('?? Gerando hash da senha...');
        const hash = await bcrypt.hash(plainPassword, saltRounds);
        
        console.log('\n' + '='.repeat(50));
        console.log('? HASH GERADO COM SUCESSO!');
        console.log('='.repeat(50));
        console.log('\n?? COPIE ESTA LINHA PARA O AZURE:');
        console.log('\x1b[32m%s\x1b[0m', `ADMIN_PASSWORD_HASH=${hash}`);
        console.log('\n' + '-'.repeat(50));
        
        // Teste de verificação
        const isValid = await bcrypt.compare(plainPassword, hash);
        console.log(`\n?? Teste de verificação: ${isValid ? '? FUNCIONANDO' : '? ERRO'}`);
        
        if (isValid) {
            console.log('\n? Tudo pronto! Agora configure esta hash no Azure.');
        }
        
    } catch (error) {
        console.error('? Erro ao gerar hash:', error.message);
    }
}

// Executar
generateHash();// JavaScript source code

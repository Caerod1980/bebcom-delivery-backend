// generate-jwt-secret.js
const crypto = require('crypto');

// Gera uma chave de 64 caracteres hexadecimais (ULTRA SEGURA)
const secret = crypto.randomBytes(64).toString('hex');

console.log('?? JWT_SECRET GERADO:');
console.log(secret);
console.log('\n?? Copie para o Azure:');
console.log(`JWT_SECRET=${secret}`);// JavaScript source code

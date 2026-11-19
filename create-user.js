'use strict';
/*
 * Crea o actualiza un locutor.
 *   node create-user.js usuario "Nombre para mostrar"
 * La contraseña se pide por teclado (no queda en el historial) o se toma de la variable
 * LOCUTOR_PASSWORD si ejecutás el comando sin interacción.
 */
const fs = require('node:fs');
const path = require('node:path');
const { hashPassword, loadEnvFile } = require('./server.js');

loadEnvFile(path.join(__dirname, '.env'));
loadEnvFile(path.join(__dirname, '..', '.env'));

const user = String(process.argv[2] || '').trim().toLowerCase();
const display = String(process.argv[3] || user).trim();
if(!/^[a-z0-9._-]{3,40}$/.test(user)){
  console.error('Uso: node create-user.js usuario "Nombre para mostrar"\nEl usuario lleva 3 a 40 letras minúsculas, números, punto, guion o guion bajo.');
  process.exit(1);
}

function askHidden(prompt){
  return new Promise(function(resolve){
    if(!process.stdin.isTTY){
      let data = '';
      process.stdin.on('data', function(c){ data += c; });
      process.stdin.on('end', function(){ resolve(data.split(/\r?\n/)[0]); });
      return;
    }
    process.stdout.write(prompt);
    process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.setEncoding('utf8');
    let pass = '';
    process.stdin.on('data', function onData(ch){
      if(ch === '\r' || ch === '\n' || ch === '\u0004'){
        process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.removeListener('data', onData);
        process.stdout.write('\n'); resolve(pass);
      } else if(ch === '\u0003'){ process.exit(1); }
      else if(ch === '\u007f'){ pass = pass.slice(0, -1); }
      else { pass += ch; }
    });
  });
}

(async function(){
  const password = process.env.LOCUTOR_PASSWORD || await askHidden('Contraseña (mínimo 10 caracteres): ');
  if(password.length < 10){ console.error('La contraseña es demasiado corta (mínimo 10 caracteres).'); process.exit(1); }
  const dir = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'users.json');
  let users = {};
  try{ users = JSON.parse(fs.readFileSync(file, 'utf8')); }catch(e){}
  users[user] = { display: display, hash: hashPassword(password), createdAt: new Date().toISOString() };
  fs.writeFileSync(file, JSON.stringify(users, null, 1), { mode: 0o600 });
  console.log('Locutor "' + user + '" guardado en ' + file);
})();

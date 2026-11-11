import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, createDecipheriv, createCipheriv, randomBytes, sign, verify } from 'node:crypto';

const required = name => {
  if (!process.env[name]) throw new Error(`Missing ${name}`);
  return process.env[name];
};
const signing = JSON.parse(required('DISCOVERY_SIGNING_KEY_JSON'));
const encryption = JSON.parse(required('DISCOVERY_AES_KEY_JSON'));
const seed = Buffer.from(signing.seed_base64, 'base64');
const aes = Buffer.from(encryption.key_base64, 'base64');
if (seed.length !== 32 || aes.length !== 32) throw new Error('Invalid key length');
const privateKey = createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
const publicKey = createPublicKey(privateKey);
const frame = fields => Buffer.concat(fields.map(field => {
  const length = Buffer.alloc(4); length.writeUInt32BE(field.length); return Buffer.concat([length,field]);
}));
const message = envelope => frame([
  Buffer.from(envelope.format),Buffer.from(envelope.key_id),Buffer.from(envelope.signing_key_id),
  Buffer.from(envelope.nonce,'base64'),Buffer.from(envelope.ciphertext,'base64'),Buffer.from(envelope.tag,'base64')
]);
const file = process.argv[2] || 'bootstrap.json';
const envelope = JSON.parse(readFileSync(file,'utf8'));
if (envelope.format !== 'nicecat-bootstrap-v1' || envelope.signing_key_id !== signing.key_id || envelope.key_id !== encryption.key_id ||
    !verify(null,message(envelope),publicKey,Buffer.from(envelope.signature,'base64'))) throw new Error('Untrusted existing manifest');
const decipher = createDecipheriv('aes-256-gcm',aes,Buffer.from(envelope.nonce,'base64'));
decipher.setAAD(Buffer.from(envelope.format));
decipher.setAuthTag(Buffer.from(envelope.tag,'base64'));
const payload = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext,'base64')),decipher.final()]).toString());
if (payload.platform_id !== 'nicecat-production' || !Number.isSafeInteger(payload.version) || payload.version < 1 ||
    !Array.isArray(payload.api_origins) || payload.api_origins.length === 0 || payload.api_origins.length > 64) throw new Error('Invalid payload');
for (const origin of payload.api_origins) {
  const uri = new URL(origin);
  if (uri.protocol !== 'https:' || uri.origin !== origin || uri.username || uri.password) throw new Error('Invalid origin');
}
const now = new Date();
if (!Number.isFinite(Date.parse(payload.expires_at))) throw new Error('Invalid expiry');
if (Date.parse(payload.expires_at) > now.getTime()+21*86400000 && process.env.FORCE_RENEW !== '1') {
  console.log('Manifest remains valid; renewal not due');
  process.exit(0);
}
payload.version += 1;
payload.expires_at = new Date(now.getTime()+30*86400000).toISOString();
const nonce = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm',aes,nonce);
cipher.setAAD(Buffer.from(envelope.format));
const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload)),cipher.final()]);
const renewed = {format:envelope.format,key_id:encryption.key_id,signing_key_id:signing.key_id,nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
renewed.signature = sign(null,message(renewed),privateKey).toString('base64');
if (!verify(null,message(renewed),publicKey,Buffer.from(renewed.signature,'base64'))) throw new Error('Renewal verification failed');
writeFileSync(file,JSON.stringify(renewed,null,2)+'\n');
console.log(`Renewed manifest version ${payload.version}, expires ${payload.expires_at}`);

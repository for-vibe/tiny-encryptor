
/* IMPORT */

import { pbkdf2Sync } from 'pbkdf2';
import { AES } from '@stablelib/aes';
import { GCM } from '@stablelib/gcm';
import getRandomBytes from 'crypto-random-uint8';
import {sha256} from 'crypto-sha';
import Int32 from 'int32-encoding';
import webcrypto from 'tiny-webcrypto';
import concat from 'uint8-concat';
import U8 from 'uint8-encoding';

/* HELPERS */

const getSubtle = () => (process?.env?.['FORCE_FALLBACK']) ? undefined : webcrypto?.subtle;

const deriveKey = async (secret: CryptoKey | Uint8Array | string, salt: Uint8Array, rounds: number): Promise<Uint8Array> => {
  const subtle = getSubtle();
  if (subtle) {
    let key: CryptoKey;
    if (secret instanceof CryptoKey) {
      key = secret;
    } else {
      const data = (typeof secret === 'string') ? U8.encode(secret.normalize()) : secret;
      key = await subtle.importKey('raw', data, { name: 'PBKDF2' }, false, ['deriveBits']);
    }
    const bits = await subtle.deriveBits({ name: 'PBKDF2', salt, iterations: rounds, hash: { name: 'SHA-256' } }, key, 32 * 8);
    return new Uint8Array(bits);
  }
  if (secret instanceof CryptoKey) throw new Error('CryptoKey secrets require WebCrypto');
  const password = (typeof secret === 'string') ? Buffer.from(secret.normalize()) : Buffer.from(secret as Uint8Array);
  const keyBuffer = pbkdf2Sync(password, Buffer.from(salt), rounds, 32, 'sha256');
  return new Uint8Array(keyBuffer);
};

/* MAIN */

const encrypt = async ( input: ArrayBuffer | Uint8Array | string, secret: CryptoKey | Uint8Array | string, salt?: Uint8Array | string, pbkdf2Rounds?: number ): Promise<Uint8Array> => {

  input = ( typeof input === 'string' ) ? U8.encode ( input ) : input;
  salt = ( typeof salt === 'string' ) ? U8.encode ( salt ) : salt || getRandomBytes ( 32 );
  salt = ( salt.length === 32 ) ? salt : await sha256.uint8 ( salt );

  const version = new Uint8Array ([ 1 ]);

  const rounds = Math.max ( 1, pbkdf2Rounds || 0 );

  const keyRaw = await deriveKey ( secret, salt, rounds );

  const iv = getRandomBytes ( 16 );

  let encryptedUint8: Uint8Array;
  const subtle = getSubtle();
  if (subtle) {
    const key = await subtle.importKey ( 'raw', keyRaw, 'AES-GCM', false, ['encrypt'] );
    const encryptedBuffer = await subtle.encrypt ( { name: 'AES-GCM', iv, length: 256, tagLength: 128 }, key, input );
    encryptedUint8 = new Uint8Array ( encryptedBuffer );
  } else {
    const aes = new AES ( keyRaw );
    const gcm = new GCM ( aes );
    (gcm as any).nonceLength = iv.length;
    encryptedUint8 = gcm.seal ( iv, new Uint8Array ( input ) );
    gcm.clean ();
  }

  const archive = concat ([ version, salt, Int32.encode ( rounds ), iv, encryptedUint8 ]); //TODO: This could be significantly optimized if somehow we didn't have to copy the uint8... 🙏

  return archive;

};

const decrypt = async ( input: Uint8Array, secret: CryptoKey | Uint8Array | string ): Promise<Uint8Array> => {

  const version = input[0];

  if ( version !== 1 ) throw new Error ( 'Unsupported encrypted archive version' );

  const salt = input.subarray ( 1, 33 );
  const rounds = Int32.decode ( input.subarray ( 33, 37 ) );
  const iv = input.subarray ( 37, 53 );
  const encrypted = input.subarray ( 53 );

  const keyRaw = await deriveKey ( secret, salt, rounds );

  let decryptedUint8: Uint8Array | null;
  const subtle = getSubtle();
  if (subtle) {
    const key = await subtle.importKey ( 'raw', keyRaw, 'AES-GCM', false, ['decrypt'] );
    const decryptedBuffer = await subtle.decrypt ( { name: 'AES-GCM', iv, length: 256, tagLength: 128 }, key, encrypted );
    decryptedUint8 = new Uint8Array ( decryptedBuffer );
  } else {
    const aes = new AES ( keyRaw );
    const gcm = new GCM ( aes );
    (gcm as any).nonceLength = iv.length;
    const opened = gcm.open ( iv, encrypted );
    gcm.clean ();
    if (!opened) throw new Error ( 'Decryption failed' );
    decryptedUint8 = opened;
  }

  return decryptedUint8;

};

/* EXPORT */

export {encrypt, decrypt};

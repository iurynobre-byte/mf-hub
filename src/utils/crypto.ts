/**
 * Cryptographic utilities implementing AES-256-GCM and SHA-256 for FlowDeck
 * Aligned with NIST SP 800-38D and OWASP Cryptographic Storage Cheat Sheet
 */

export async function sha256(text: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function generateRandomKeyId(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return 'key_' + Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

export function generateHex(bytes: number = 16): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Derives a 256-bit AES-GCM CryptoKey from a passphrase using PBKDF2 with 100,000 iterations
 */
export async function deriveKeyFromPassphrase(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a JSON payload or string with AES-GCM 256-bit
 */
export async function encryptAESGCM(data: string, passphrase: string): Promise<{
  ciphertext: string;
  iv: string;
  salt: string;
  authTag: string;
  algorithm: string;
}> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV recommended for GCM

  const key = await deriveKeyFromPassphrase(passphrase, salt);
  const encodedData = enc.encode(data);

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128
    },
    key,
    encodedData
  );

  // In Web Crypto AES-GCM, the last 16 bytes of encryptedBuffer are the authentication tag
  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const tagLengthBytes = 16;
  const ciphertextBytes = encryptedBytes.slice(0, encryptedBytes.length - tagLengthBytes);
  const authTagBytes = encryptedBytes.slice(encryptedBytes.length - tagLengthBytes);

  return {
    ciphertext: btoa(String.fromCharCode(...ciphertextBytes)),
    iv: btoa(String.fromCharCode(...iv)),
    salt: btoa(String.fromCharCode(...salt)),
    authTag: btoa(String.fromCharCode(...authTagBytes)),
    algorithm: 'AES-256-GCM'
  };
}

/**
 * Decrypts an AES-GCM encrypted payload
 */
export async function decryptAESGCM(
  ciphertextBase64: string,
  ivBase64: string,
  saltBase64: string,
  authTagBase64: string,
  passphrase: string
): Promise<string> {
  try {
    const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
    const cipherBytes = Uint8Array.from(atob(ciphertextBase64), c => c.charCodeAt(0));
    const tagBytes = Uint8Array.from(atob(authTagBase64), c => c.charCodeAt(0));

    // Combine ciphertext and authTag for Web Crypto API decryption
    const combined = new Uint8Array(cipherBytes.length + tagBytes.length);
    combined.set(cipherBytes, 0);
    combined.set(tagBytes, cipherBytes.length);

    const key = await deriveKeyFromPassphrase(passphrase, salt);
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      key,
      combined
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch (err) {
    throw new Error('Falha na descriptografia: chave inválida ou integridade do pacote violada.');
  }
}

/**
 * Calculates entropy of a string (bits of entropy)
 */
export function calculateEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const frequencies = new Map<string, number>();

  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Math.round(entropy * len * 10) / 10;
}

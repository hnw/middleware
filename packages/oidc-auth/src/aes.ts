/**
 * Generates a CryptoKey from the given password for encryption/decryption.
 * @param password The password string. It is recommended that the password be at least 32 bytes for better entropy.
 * @returns The generated CryptoKey.
 */
const getKey = async (password: string): Promise<CryptoKey> => {
  const encoder = new TextEncoder()
  return await crypto.subtle.importKey(
    'raw',
    await crypto.subtle.digest('SHA-256', encoder.encode(password)),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt']
  )
}

/**
 * Generates an initialization vector (IV) for encryption.
 * @returns The generated Uint8Array IV.
 */
const generateIV = (): Uint8Array => {
  return crypto.getRandomValues(new Uint8Array(12))
}

/**
 * Encrypts the given plain text with the given password.
 * @param plainText The plain text to encrypt.
 * @param password The password to use for encryption.
 * @returns The encrypted string (Base64 encoded).
 */
export const encrypt = async (plainText: string, password: string): Promise<string> => {
  const encoder = new TextEncoder()
  const iv = generateIV()
  const key = await getKey(password)
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    encoder.encode(plainText)
  ));
  return encodeCipherText(iv, encrypted)
}

/**
 * Encodes the initialization vector (IV) and encrypted data into a Base64 string.
 * @param iv The initialization vector.
 * @param encrypted The encrypted data.
 * @returns The Base64 encoded string.
 */
const encodeCipherText = (iv: Uint8Array, encrypted: Uint8Array): string => {
  const combined = new Uint8Array([...iv, ...encrypted])
  return btoa(String.fromCharCode(...combined))
}

/**
 * Decodes the Base64 encoded string into the initialization vector (IV) and encrypted data.
 * @param cipherText The Base64 encoded string.
 * @returns An object containing the IV and encrypted data.
 */
const decodeCipherText = (cipherText: string): { iv: Uint8Array, encrypted: Uint8Array } => {
  const combined = Uint8Array.from(atob(cipherText), c => c.charCodeAt(0))
  const iv = combined.slice(0, 12)
  const encrypted = combined.slice(12)
  return { iv, encrypted }
}

/**
 * Decrypts the given encrypted string with the given password.
 * @param cipherText The encrypted string to decrypt (Base64 encoded).
 * @param password The password to use for decryption.
 * @returns The decrypted plain text, or an empty string if decryption fails.
 */
export const decrypt = async (cipherText: string, password: string): Promise<string> => {
  const decoder = new TextDecoder()
  const { iv, encrypted } = decodeCipherText(cipherText)
  const key = await getKey(password)
  try {
    const decrypted = new Uint8Array(await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      key,
      encrypted
    ))
    return decoder.decode(decrypted)
  } catch (e) {
    throw new Error(`AES-GCM decryption failed: ${e}`);
  }
}

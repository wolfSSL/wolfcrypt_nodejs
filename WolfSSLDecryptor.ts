const wolfcrypt = require('./build/Release/wolfcrypt');

//export class WolfSSLDecryptor implements Decryptor {
export class WolfSSLDecryptor {
  private evp: Buffer
  private totalInputLength: number

  /**
   * Initializes a new instance of the WolfSSLDecryptor class.
   *
   * @param cipher The cipher name to use.
   * @param key    The decryption key to use.
   * @param iv     The initialization vector.
   *
   * @throws {Error} If cipher is not available or unknown.
   * @throws {Error} If the creation of the Decryption object failed.
   */
  public constructor(cipher: string, key: Buffer, iv: Buffer) {
    //this.enableFips();
    this.evp = Buffer.alloc( wolfcrypt.sizeof_EVP_CIPHER_CTX() )
    this.totalInputLength = 0
    wolfcrypt.EVP_CipherInit( this.evp, cipher, key, iv )
  }

  /**
   * Updates the internal state with data for decryption.
   *
   * @param data The data that will be added for decryption.
   *
   * @returns The decrypted data if possible.
   *
   * @throws {Error} If the decryption fails.
   *
   * @remarks This function should be called multiple times.
   */
  public update(data: Buffer): Buffer {
    this.totalInputLength += data.length

    let outBuffer = Buffer.alloc( this.totalInputLength )

    let ret = wolfcrypt.EVP_CipherUpdate( this.evp, outBuffer, data, data.length )

    if ( ret > 0 )
    {
      return outBuffer
    }

    return Buffer.alloc( 0 )
  }

  /**
   * Finalize the decryption process.
   *
   * @returns The last block of decrypted data.
   *
   * @throws {Error} If the decryption fails.
   *
   * @remarks This function should be called once to finalize the decryption
   * process.
   */
  public finalize(): Buffer {
    this.totalInputLength += this.totalInputLength % 16;

    let outBuffer = Buffer.alloc( this.totalInputLength )

    let ret = wolfcrypt.EVP_CipherFinal( this.evp, outBuffer )

    if ( ret > 0 )
    {
      return outBuffer
    }

    return Buffer.alloc( 0 )
  }

  /**
   * Enables the FIPS mode.
   */
  /*
  private enableFips(): void {
    if (!wolfssl.isFipsEnabled() && !wolfssl.enableFips()) {
      logger.logWarning('FIPS mode not available.');
    }
  }
  */
}

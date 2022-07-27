const wolfcrypt = require( './build/Release/wolfcrypt' );
const stream = require( 'stream' );

class WolfSSLEVP
{
  // actually holds a pointer but nodejs has no pointer type
  protected evp: number = null
  protected totalInputLength: number = 0

  public constructor()
  {
    this.evp = wolfcrypt.EVP_CIPHER_CTX_new()
    this.totalInputLength = 0
  }

  /**
   * Updates the internal state with data for cipher.
   *
   * @param data The data that will be added to the cipher.
   *
   * @returns The result data if possible.
   *
   * @throws {Error} If the decryption fails.
   *
   * @remarks This function should be called multiple times.
   */
  public update(data: Buffer): Buffer
  {
    if ( this.evp == null )
    {
      throw 'Cipher is not allocated'
    }

    this.totalInputLength += data.length

    let outBuffer = Buffer.alloc( this.totalInputLength )

    let ret = wolfcrypt.EVP_CipherUpdate( this.evp, outBuffer, data, data.length )

    if ( ret < 0 )
    {
      throw 'Failed to update cipher'
    }

    if ( ret > 0 )
    {
      this.totalInputLength -= ret;

      return outBuffer.subarray( 0, ret )
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
  public finalize(): Buffer
  {
    if ( this.evp == null )
    {
      throw 'Cipher is not allocated'
    }

    if ( this.totalInputLength % 16 != 0 )
    {
      this.totalInputLength += ( 16 - this.totalInputLength % 16 )
    }

    let outBuffer = Buffer.alloc( this.totalInputLength )
    this.totalInputLength = 0;

    let ret = wolfcrypt.EVP_CipherFinal( this.evp, outBuffer )

    wolfcrypt.EVP_CIPHER_CTX_free( this.evp )
    this.evp = null

    if ( ret < 0 )
    {
      throw 'Failed to finalize cipher'
    }

    if ( ret > 0 )
    {
      return outBuffer.subarray( 0, ret )
    }

    return Buffer.alloc( 0 )
  }

  public free()
  {
    if ( this.evp != null )
    {
      wolfcrypt.EVP_CIPHER_CTX_free( this.evp )
      this.evp = null
    }
    else
    {
      throw 'Cipher is not allocated'
    }
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

export class WolfSSLEncryptor extends WolfSSLEVP
{
  /**
   * Initializes a new instance of the WolfSSLEncryptor class.
   *
   * @param cipher The cipher name to use.
   * @param key    The decryption key to use.
   * @param iv     The initialization vector.
   *
   * @throws {Error} If cipher is not available or unknown.
   * @throws {Error} If the creation of the Decryption object failed.
   */
  public constructor(cipher: string, key: Buffer, iv: Buffer)
  {
    super()
    wolfcrypt.EVP_CipherInit( this.evp, cipher, key, iv, 1 )
  }
}

export class WolfSSLDecryptor extends WolfSSLEVP {
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
  public constructor(cipher: string, key: Buffer, iv: Buffer)
  {
    super()
    wolfcrypt.EVP_CipherInit( this.evp, cipher, key, iv, 0 )
  }
}

export class WolfSSLEncryptionStream extends stream.Transform
{
  private encryptor: WolfSSLEncryptor
  /**
   * Initializes a new instance of the WolfSSLEncryptionStream class.
   *
   * @param cipher The cipher name to use.
   * @param key    The decryption key to use.
   * @param iv     The initialization vector.
   *
   * @throws {Error} If cipher is not available or unknown.
   * @throws {Error} If the creation of the Decryption object failed.
   */
  public constructor(cipher: string, key: Buffer, iv: Buffer)
  {
    super()
    this.encryptor = new WolfSSLEncryptor( cipher, key, iv )
  }

  public _transform( chunk: Buffer, enc: BufferEncoding, cb: Function )
  {
    let buffer = Buffer.isBuffer( chunk ) ? chunk: new Buffer( chunk, enc )

    let ret_buffer = this.encryptor.update( chunk )

    if ( ret_buffer.length > 0 )
    {
      this.push( ret_buffer )
    }

    cb()
  }

  public _flush( cb: Function )
  {
    let ret_buffer = this.encryptor.finalize()

    if ( ret_buffer.length > 0 )
    {
      this.push( ret_buffer )
    }

    cb()
  }
}

export class WolfSSLDecryptionStream extends stream.Transform {
  private encryptor: WolfSSLEncryptor
  /**
   * Initializes a new instance of the WolfSSLEncryptionStream class.
   *
   * @param cipher The cipher name to use.
   * @param key    The decryption key to use.
   * @param iv     The initialization vector.
   *
   * @throws {Error} If cipher is not available or unknown.
   * @throws {Error} If the creation of the Decryption object failed.
   */
  public constructor(cipher: string, key: Buffer, iv: Buffer)
  {
    super()
    this.encryptor = new WolfSSLDecryptor( cipher, key, iv )
  }

  public _transform( chunk: Buffer, enc: BufferEncoding, cb: Function )
  {
    let buffer = Buffer.isBuffer( chunk ) ? chunk: new Buffer( chunk, enc )

    let ret_buffer = this.encryptor.update( chunk )

    if ( ret_buffer.length > 0 )
    {
      this.push( ret_buffer )
    }

    cb()
  }

  public _flush( cb: Function )
  {
    let ret_buffer = this.encryptor.finalize()

    if ( ret_buffer.length > 0 )
    {
      this.push( ret_buffer )
    }

    cb()
  }
}

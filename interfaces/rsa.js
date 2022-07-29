const wolfcrypt = require( '../build/Release/wolfcrypt' );

class WolfSSLRsa
{
  constructor()
  {
    this.rsa = Buffer.alloc( wolfcrypt.sizeof_RsaKey() )
    this.size = -1
    wolfcrypt.wc_InitRsaKey( this.rsa )
  }

  MakeRsaKey( size, e )
  {
    this.size = size

    let ret = wolfcrypt.wc_MakeRsaKey( this.rsa, size, e )

    if ( ret != 0 )
    {
      throw `Failed to wc_MakeRsaKey ${ ret }`
    }
  }

  RsaKeyToDer()
  {
    if ( this.size == -1 || this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    let derBuf = Buffer.alloc( this.size )

    let ret = wolfcrypt.wc_RsaKeyToDer( this.rsa, derBuf, this.size )

    if ( ret <= 0 )
    {
      throw `Failed to wc_RsaKeyToDer ${ ret }`
    }

    return derBuf
  }

  RsaPrivateKeyDecode( derBuf )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    let ret = wolfcrypt.wc_RsaPrivateKeyDecode( derBuf, this.rsa, derBuf.length )

    if ( ret != 0 )
    {
      throw `Failed to wc_RsaPrivateKeyDecode ${ ret }`
    }
  }

  RsaPublicKeyDecode( derBuf )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    let ret = wolfcrypt.wc_RsaPublicKeyDecode( derBuf, this.rsa, derBuf.length )

    if ( ret != 0 )
    {
      throw `Failed to wc_RsaPublicKeyDecode ${ ret }`
    }
  }

  RsaPublicEncrypt( data )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    let ciphertext = Buffer.alloc( wolfcrypt.wc_RsaEncryptSize( this.rsa ) )

    let ret = wolfcrypt.wc_RsaPublicEncrypt( data, data.length, ciphertext, ciphertext.length, this.rsa )

    if ( ret <= 0 )
    {
      throw `Failed to wc_RsaPublicEncrypt ${ ret }`
    }

    return ciphertext
  }

  RsaPrivateDecrypt( ciphertext )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    if ( !Buffer.isBuffer( ciphertext ) )
    {
      throw `ciphertext must be a Buffer`
    }

    let data = Buffer.alloc( wolfcrypt.wc_RsaEncryptSize( this.rsa ) )

    let ret = wolfcrypt.wc_RsaPrivateDecrypt( ciphertext, ciphertext.length, data, data.length, this.rsa )

    if ( ret <= 0 )
    {
      throw `Failed to wc_RsaPrivateDecrypt ${ ret }`
    }

    return ciphertext
  }

  FreeRsaKey()
  {
    wolfcrypt.wc_FreeRsaKey( this.rsa )
    this.rsa = null
  }
}

exports.WolfSSLRsa = WolfSSLRsa

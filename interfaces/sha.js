const wolfcrypt = require( '../build/Release/wolfcrypt' )

class WolfSSLSha
{
  constructor( type )
  {
    let ret;

    this.sha = null
    this.digestLength = -1

    switch ( type )
    {
      case 'SHA':
        this.sha = Buffer.alloc( wolfcrypt.sizeof_WOLFSSL_SHA_CTX() )

        ret = wolfcrypt.wolfSSL_SHA_Init( this.sha )

        if ( ret != 1 )
        {
          throw `Failed to wolfSSL_SHA_Init ${ ret }`
        }

        this.updateSpecific = wolfcrypt.wolfSSL_SHA_Update
        this.finalizeSpecific = wolfcrypt.wolfSSL_SHA_Final

        break;
      case 'SHA224':
        this.sha = Buffer.alloc( wolfcrypt.sizeof_WOLFSSL_SHA224_CTX() )

        ret = wolfcrypt.wolfSSL_SHA224_Init( this.sha )

        if ( ret != 1 )
        {
          throw `Failed to wolfSSL_SHA_Init ${ ret }`
        }

        this.updateSpecific = wolfcrypt.wolfSSL_SHA224_Update
        this.finalizeSpecific = wolfcrypt.wolfSSL_SHA224_Final

        break;
      case 'SHA256':
        this.sha = Buffer.alloc( wolfcrypt.sizeof_WOLFSSL_SHA256_CTX() )

        ret = wolfcrypt.wolfSSL_SHA256_Init( this.sha )

        if ( ret != 1 )
        {
          throw `Failed to wolfSSL_SHA_Init ${ ret }`
        }

        this.updateSpecific = wolfcrypt.wolfSSL_SHA256_Update
        this.finalizeSpecific = wolfcrypt.wolfSSL_SHA256_Final

        break;
      case 'SHA384':
        this.sha = Buffer.alloc( wolfcrypt.sizeof_WOLFSSL_SHA384_CTX() )

        ret = wolfcrypt.wolfSSL_SHA384_Init( this.sha )

        if ( ret != 1 )
        {
          throw `Failed to wolfSSL_SHA_Init ${ ret }`
        }

        this.updateSpecific = wolfcrypt.wolfSSL_SHA384_Update
        this.finalizeSpecific = wolfcrypt.wolfSSL_SHA384_Final

        break;
      case 'SHA512':
        this.sha = Buffer.alloc( wolfcrypt.sizeof_WOLFSSL_SHA512_CTX() )

        ret = wolfcrypt.wolfSSL_SHA512_Init( this.sha )

        if ( ret != 1 )
        {
          throw `Failed to wolfSSL_SHA_Init ${ ret }`
        }

        this.updateSpecific = wolfcrypt.wolfSSL_SHA512_Update
        this.finalizeSpecific = wolfcrypt.wolfSSL_SHA512_Final

        break;
      case 'SHA512_224':
        this.sha = Buffer.alloc( wolfcrypt.sizeof_WOLFSSL_SHA512_224_CTX() )

        ret = wolfcrypt.wolfSSL_SHA512_224_Init( this.sha )

        if ( ret != 1 )
        {
          throw `Failed to wolfSSL_SHA_Init ${ ret }`
        }

        this.updateSpecific = wolfcrypt.wolfSSL_SHA512_224_Update
        this.finalizeSpecific = wolfcrypt.wolfSSL_SHA512_224_Final

        break;
      case 'SHA512_256':
        this.sha = Buffer.alloc( wolfcrypt.sizeof_WOLFSSL_SHA512_256_CTX() )

        ret = wolfcrypt.wolfSSL_SHA512_256_Init( this.sha )

        if ( ret != 1 )
        {
          throw `Failed to wolfSSL_SHA_Init ${ ret }`
        }

        this.updateSpecific = wolfcrypt.wolfSSL_SHA512_256_Update
        this.finalizeSpecific = wolfcrypt.wolfSSL_SHA512_256_Final

        break;
      default:
        throw 'Invalid Sha type'

        break;
    }

    this.digestLength = wolfcrypt.Sha_digest_length( type )

    if ( this.digestLength < 0 )
    {
      throw 'Invalid Sha type'
    }

    this.type = type
  }

  update( data )
  {
    if ( this.sha == null )
    {
      throw 'Sha is not allocated'
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    let ret = this.updateSpecific( this.sha, data, data.length )

    if ( ret != 1 )
    {
      throw `Failed to update Sha ${ ret }`
    }
  }

  finalize()
  {
    if ( this.sha == null )
    {
      throw 'Sha is not allocated'
    }

    let digest = Buffer.alloc( this.digestLength )

    let ret = this.finalizeSpecific( digest, this.sha )

    if ( ret != 1 )
    {
      throw `Failed to final Sha ${ ret }`
    }

    return digest
  }
}

exports.WolfSSLSha = WolfSSLSha

const evp_tests = require( './tests/evp' );
const hmac_tests = require( './tests/hmac' );
const rsa_tests = require( './tests/rsa' );

(async function() {
  for ( const key of Object.keys( evp_tests ) )
  {
    await evp_tests[key]()
  }

  for ( const key of Object.keys( hmac_tests ) )
  {
    await hmac_tests[key]()
  }

  for ( const key of Object.keys( rsa_tests ) )
  {
    await rsa_tests[key]()
  }
})()

const fs = require( 'fs' )
const path = require( 'path' )
const interfaces = path.join( __dirname, 'interfaces' )
const wolfcrypt = require( path.join( __dirname, 'build/Release/wolfcrypt' ) );
const actions = {}

actions.wolfcrypt = wolfcrypt

fs.readdirSync( interfaces )
  .filter ( file => {
    return ( file.indexOf( '.' ) !== 0 ) && ( file.slice( -3 ) === '.js' )
  } )
  .forEach( file => {
    const face = require( path.join( interfaces, file ) )

    for ( const key of Object.keys( face ) )
    {
      actions[key] = face[key]
    }
  } )

module.exports = actions

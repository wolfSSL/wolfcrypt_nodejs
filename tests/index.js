const fs = require( 'fs' )
const path = require( 'path' )
const basename = path.basename( __filename )
const actions = {};

fs.readdirSync( __dirname )
  .filter ( file => {
    return ( file.indexOf( '.' ) !== 0 ) && ( file !== basename ) && ( file.slice( -3 ) === '.js' )
  } )
  .forEach( file => {
    const tests = require( path.join( __dirname, file ) )

    for ( const key of Object.keys( tests ) )
    {
      actions[key] = tests[key]
    }
  } )

module.exports = actions

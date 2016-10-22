'use strict';
/* ഓം ബ്രഹ്മാർപ്പണം  */

const log = require('debug')('paricha');


/* Implementation of lodash.get function */
function getProp( object, keys ){
  keys = Array.isArray( keys )? keys : keys.split('.');
  object = object[keys[0]];
  if( object && keys.length>1 ){
    return getProp( object, keys.slice(1) );
  }
  return object;
}



class AccessChecker {


  static actionName( serviceName, method ){
    return serviceName + ':' + method;
  }


  static Permission( isGranted, message ){
    message = message || '';
    return { isGranted, message };
  }


  static applyInheritance( compiledAcls, items, parent ){
    items.forEach( function( item ){
      if( parent ){
        Object.assign( compiledAcls[item.role], compiledAcls[parent.role] );
      }
      this.applyInheritance( compiledAcls, item.children, item );
    }, this );
  }


  static listToTree( nodes ){
    var map = {},
      node,
      roots = [],
      i,
      l = nodes.length;

    for ( i = 0; i < l; i++) {
      node = nodes[i];
      node.children = [];
      map[node.role] = node;
      if ( node.parent ) {
        map[node.parent].children.push(node);
      } else {
        roots.push(node);
      }
    }

    return roots;
  }


  constructor( acl ){
    var roleName,
      rawAcl = [];
    for ( roleName in acl ){
      acl[roleName].role = roleName;
      rawAcl.push( acl[roleName] );
    }
    this._rawACL = rawAcl;
    this.compiledAcls = {};

    this.compileACL();
  }

  checkAccess( serviceName ){
    const checker = this;
    return function( hook ){
      const params = hook.params;
      const permission = checker.getPermission( serviceName, hook );
      log( 'Checking access for ' + serviceName + ' : ' + hook.method );

      if( permission.isGranted ){
        return hook;
      }
      return Promise.reject( permission.message );
    };
  }


  getPermission( serviceName, hook ){
    const method = hook.method;
    const action = AccessChecker.actionName( serviceName, method );
    const role = getProp( hook, 'params.user.role' ) || 'guest' ;
    const acl = this.compiledAcls[role]||{};
    const access = acl[ action ] || acl['*'];
    log( 'Role: ' + role );
    log( 'access: ' + access );

    if( !access ){
      return Promise.resolve( AccessChecker.Permission( false, AccessChecker.MSG_DENIED ) );
    }

    if( !access.when ){
      return Promise.resolve( AccessChecker.Permission( true ) );
    }

    return Promise.resolve( access.when( hook.params, hook ) )
      .then( function( status ){
        if( status ){
          return AccessChecker.Permission( true );
        }
        return AccessChecker.Permission( false, 'Access Denied' );
      });
  }

  compileACL(){
    this._rawACL.forEach( ( item ) => {
      var compiledRole = {};
      this.compiledAcls[ item.role ] = compiledRole;
      item.allow = item.allow || [];
      item.allow.forEach( function( v ){
        compiledRole[v.action || v ] = v;
      });
    });
    AccessChecker.applyInheritance( this.compiledAcls, AccessChecker.listToTree( this._rawACL ) );
  }

}

AccessChecker.MSG_DENIED = 'Access Denied';

module.exports = AccessChecker;

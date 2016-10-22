require( 'simple-mocha' );
const AccessChecker = require( '../index' );
const assert = require('assert');
const _ = require('lodash');


var testAcl = {
  guest:{
    parent: null,
    allow:[
      'session:create'
    ],
  },

  user:{
    parent: 'guest',
    allow: [
      'bookmark:create'
    ]
  },

  agent: {
    parent: 'user',
    allow: [
      'user:list',
      'invitation:create',
    ]
  },

  officer:{
    parent: 'user',
    allow:[
      'user:list',
      'invitation:list',
      'invitation:remove',
    ]
  },

  admin:{
    parent: 'officer',
    allow: [ '*' ]
  }
};


describe( 'AccessChecker', function(){

  var inst = new AccessChecker( testAcl );

  it( 'should initialize', function( ){

    assert.ok( inst );
    assert.ok( Array.isArray( inst._rawACL ) );

  });

  it( 'should compile all given roles', function(){
    var givenRoleNames = _.keys( testAcl ).sort();
    var roleNames = _.map( inst._rawACL, 'role' ).sort();
    var compiledRoleNames = _.keys( inst.compiledAcls ).sort();

    assert.deepEqual( givenRoleNames, roleNames );
    assert.deepEqual( givenRoleNames, compiledRoleNames );
  });

  it( 'should apply the the role inheritance', function(){
    var ip = {},
      op = {},
      roleName;
    ip.roleHashMap = _.keyBy( inst._rawACL, 'role' );
    op.roleHashMap = inst.compiledAcls;


    for ( roleName in ip.roleHashMap ){
      ip.role = ip.roleHashMap[roleName];
      ip.allowdActions = ip.role.allow.map( v => ( v.action|| v ) );

      op.role = op.roleHashMap[roleName];
      op.allowdActions = _.keys( op.role );

      assert.equal(
        _.difference( ip.allowdActions, op.allowdActions ),
        0,
        'Compiled acl should contain the the acl given the raw initialization data'
      );

      if( ip.role.parent ){
        var parentsAllowdActions = _.keys( op.roleHashMap[ ip.role.parent ] );
        assert.equal(
          _.difference( parentsAllowdActions, op.allowdActions ),
          0,
          'Compiled acl should contain the the acl of its parent role'
        );
      }

    }
  });


  it( 'should check the persmission properly', function( ){

    const guestUser = { role: 'guest' };
    const normalUser = { role: 'user' };
    const adminUser = { role: 'admin' };
    const getPermission = function( user, service, method ){
      const params = { user };
      const out = inst.getPermission( service, { method, params } );
      return out.isGranted;
    };

    assert.ok( getPermission( guestUser, 'session',  'create' ) );
    assert.ifError(  getPermission( guestUser, 'session',  'list' )  );
    assert.ifError(  getPermission( guestUser, 'bookmark',  'create' )  );

    assert.ok(  getPermission( normalUser, 'session',  'create' )  );
    assert.ok(  getPermission( normalUser, 'bookmark',  'create' )  );
    assert.ifError(  getPermission( normalUser, 'session',  'list' )  );

    assert.ok(  getPermission( adminUser, 'session',  'create' )  );
    assert.ok(  getPermission( adminUser, 'bookmark',  'create' )  );
    assert.ok(  getPermission( adminUser, 'session',  'list' )  );
  });

});

require( 'simple-mocha' );
const AccessChecker = require( '../index' );
const assert = require('assert');
const _ = require('lodash');
const Promise = require('bluebird');

const Bookmark = {
  items:{
    1:{
      user: 113
    }
  },
  get: function( id ){
    return Promise.resolve( this.items[id] );
  },
};


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
      'bookmark:create',
      {
        action:'bookmark:update',
        when: function( params, hook ){
          return params.bookmark.user === params.user.id;
        }
      },
      {
        action:'bookmark:delete',
        when: function( params, hook ){
          return Bookmark.get( hook.id )
            .then( function( bookmark ){
              return bookmark.user === params.user.id;
            });
        }
      }
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


  describe( 'should check the persmission properly', function(){

    const guestUser = { role: 'guest' };
    const normalUser = { role: 'user', id: 112 };
    const adminUser = { role: 'admin' };
    const getPermission = function( user, service, method ){
      const params = { user, bookmark:{ user: 111 } };
      const out = inst.getPermission( service, { method, params, id: 1 } );
      return out;
    };

    let permission;


    it( 'should check permissions without any conditions', function( done ){
      Promise.coroutine( function*(){
        permission = yield  getPermission( guestUser, 'session',  'create' );
        assert.ok( permission.isGranted );
        permission = yield getPermission( guestUser, 'session',  'list' )  ;
        assert.ifError( permission.isGranted );
        permission = yield getPermission( guestUser, 'bookmark',  'create' )  ;
        assert.ifError( permission.isGranted );

        permission = yield getPermission( normalUser, 'session',  'create' )  ;
        assert.ok( permission.isGranted );
        permission = yield getPermission( normalUser, 'bookmark',  'create' )  ;
        assert.ok( permission.isGranted );
        permission = yield getPermission( normalUser, 'session',  'list' )  ;
        assert.ifError( permission.isGranted );
        permission = yield getPermission( normalUser, 'bookmark',  'update' )  ;
        assert.ifError( permission.isGranted );

        permission = yield getPermission( adminUser, 'session',  'create' )  ;
        assert.ok( permission.isGranted );
        permission = yield getPermission( adminUser, 'bookmark',  'create' )  ;
        assert.ok( permission.isGranted );
        permission = yield getPermission( adminUser, 'session',  'list' )  ;
        assert.ok( permission.isGranted );
      })().asCallback( done );
    });


    it( 'should check permissions with syncronous conditions', function( done ){
      Promise.coroutine( function*(){
        normalUser.id = 111;
        permission = yield getPermission( normalUser, 'bookmark',  'update' )  ;
        assert.ok( permission.isGranted );

      })().asCallback( done );
    });


    it( 'should check permissions with syncronous conditions', function( done ){
      Promise.coroutine( function*(){
        normalUser.id = 113;
        permission = yield getPermission( normalUser, 'bookmark',  'delete' )  ;
        assert.ok( permission.isGranted );
      })().asCallback( done );
    });


  });

});

package com.fuyongbin;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.ArrayList;

public class Realm extends AuthorizingRealm {
    /*认证*/
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
       /*获取用户名*/
        String username = (String) authenticationToken.getPrincipal();
        String name="itlike";
        String password="123456";
        if (!name.equals(username)){
            return null;
        }
        /*交由认证器去认证*/
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(username, password, this.getName());
        return simpleAuthenticationInfo;
    }
    /*授权*/
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        /*获取身份信息*/
        Object primaryPrincipal = principalCollection.getPrimaryPrincipal();
        ArrayList<String> roles = new ArrayList<>();
        roles.add("role1");
        roles.add("role2");
        ArrayList<String> permissions = new ArrayList<>();
        permissions.add("user:create");
        permissions.add("user:upda te");

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.addRoles(roles);
        simpleAuthorizationInfo.addStringPermissions(permissions);
        return simpleAuthorizationInfo;
    }


}

package com.mmall.demo2;

import com.mmall.demo2.model.Permission;
import com.mmall.demo2.model.Role;
import com.mmall.demo2.model.User;
import com.mmall.demo2.service.UserService;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

public class AuthRealm extends AuthorizingRealm {
    @Autowired
    private UserService userService;
    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        User user = (User)principalCollection.fromRealm(this.getClass().getName()).iterator().next();
        List<String> permissionList = new ArrayList<>();
        List<String> romeNameList = new ArrayList<>();
        //通过用户获取权限
        Set<Role> roleSet = user.getRoles();
        if(CollectionUtils.isNotEmpty(roleSet)){
            for(Role role : roleSet){
                romeNameList.add(role.getRname());
                Set<Permission> permissionsSet = role.getPermissions();
                if(CollectionUtils.isNotEmpty(permissionsSet)){
                    for(Permission permission : permissionsSet){
                        permissionList.add(permission.getName());
                    }
                }
            }
        }
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.addStringPermissions(permissionList);
        simpleAuthorizationInfo.addRoles(romeNameList);
        return simpleAuthorizationInfo;
    }

    //登陆认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) authenticationToken;
        String username = usernamePasswordToken.getUsername();
        User user = userService.findByUsername(username);
        return new SimpleAuthenticationInfo(user,user.getPassword(),this.getClass().getName());
    }
}

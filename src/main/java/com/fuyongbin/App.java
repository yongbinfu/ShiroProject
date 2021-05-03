package com.fuyongbin;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;

import javax.xml.transform.Source;
import java.util.Arrays;

/**
 * Hello world!
 */
public class App {
    public  void test1() {
       /* 1.构建securityManager工厂
        2.通过工厂创建securityManager
        3.将securityManager设置到运行环境中
        4.创建一个Subject实例
        5.创建token令牌
        6.用户登录
        7.用户退出*/
        /* 1.构建securityManager工厂*/
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        /*2.通过工厂创建securityManager*/
        SecurityManager securityManager = factory.getInstance();
        /*3.将securityManager设置到运行环境中*/
        SecurityUtils.setSecurityManager(securityManager);
        /*4.创建一个Subject(主体)实例*/
        Subject subject = SecurityUtils.getSubject();
        /*5.创建token令牌*/
        UsernamePasswordToken token = new UsernamePasswordToken("itlike", "123456");
        try {
            /*6.用户登录*/
            subject.login(token);
            System.out.println("登录成功");
        }catch (UnknownAccountException e){
            System.out.println("用户不存在");
            e.printStackTrace();
        }catch (IncorrectCredentialsException e){
            System.out.println("密码错误");
            e.printStackTrace();
        }
        System.out.println("是否认证成功"+subject.isAuthenticated());
        /*7.用户退出*/
        subject.logout();
        System.out.println("是否认证成功"+subject.isAuthenticated());
    }

    public void test2(){
        /*散列密码  每次的加密都是一样的，所以会被MD5解析工具进行解析（不安全）*/
        /*使用散列密码的时候一般情况下都会对密码进行加盐然后对数据进行2次或者是三次的散列*/
        Md5Hash md5Hash = new Md5Hash("1223254565","fuyongbin",3);
        System.out.println(md5Hash.toString());

        SimpleHash simpleHash = new SimpleHash("md5", "123456", "fuyongbin", 3);
        System.out.println(simpleHash);

    }
    public void test3(){
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        /*2.通过工厂创建securityManager*/
        SecurityManager securityManager = factory.getInstance();
        /*3.将securityManager设置到运行环境中*/
        SecurityUtils.setSecurityManager(securityManager);
        /*4.创建一个Subject(主体)实例*/
        Subject subject = SecurityUtils.getSubject();
        /*5.创建token令牌*/
        UsernamePasswordToken token = new UsernamePasswordToken("itlike", "123456");
        try {
            /*6.用户登录*/
            subject.login(token);
            System.out.println("登录成功");
        }catch (UnknownAccountException e){
            System.out.println("用户不存在");
            e.printStackTrace();
        }catch (IncorrectCredentialsException e){
            System.out.println("密码错误");
            e.printStackTrace();
        }
        System.out.println("是否认证成功"+subject.isAuthenticated());
     /*   在认证成功之后才去做授权
        判断当前的用户是否有某一个角色和某一个权限
        判断当前用户有没有角色1*/
        System.out.println(subject.hasRole("role1"));
        System.out.println(subject.hasRole("role2"));
        System.out.println(subject.hasRole("role3"));
     /*   判断当前角色是否包含多个角色*/
        System.out.println(subject.hasAllRoles(Arrays.asList("role1","role2")));

        /*判断是否有某一个权限*/
        System.out.println(subject.isPermitted("user:create"));
        /*判断是否同时有多个权限*/
        System.out.println(subject.isPermittedAll("user:update","user:create"));
    }
    public static void main(String[] args) {
        App app = new App();
        app.test2();
    }
}

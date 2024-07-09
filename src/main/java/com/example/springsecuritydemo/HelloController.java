package com.example.springsecuritydemo;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

//    @PreAuthorize("hasRole('ADMIN')") //this to work, enable method security in Config
    @GetMapping("/admin/hello")
    public String sayHelloAdmin(){
        return "Hello Admin";
    }


//    @PreAuthorize("hasRole('USER')") //this to work, enable method security in Config
    @GetMapping("/user/hello")
    public String sayHelloUser(){
        return "Hello User";
    }
}

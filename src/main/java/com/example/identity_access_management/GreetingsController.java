package com.example.identity_access_management;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

    @GetMapping("/hello")
    public String sayHello(){
        return "Hello";
    }

    @GetMapping("/developer")
    @PreAuthorize("hasRole('DEVELOPER')")
    public String sayDeveloper(){
        return "Developer";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String sayAdmin(){
        return "Admin";
    }
}

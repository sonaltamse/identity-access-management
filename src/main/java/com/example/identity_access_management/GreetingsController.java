package com.example.identity_access_management;

import com.example.identity_access_management.jwt.JwtUtils;
import com.example.identity_access_management.jwt.LoginRequest;
import com.example.identity_access_management.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingsController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

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

    @PostMapping("/signin")
    public ResponseEntity<Object> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;
        Map<String, Object> map = new HashMap<>();
        try{
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getusername(),
                            loginRequest.getPassword()
                    )
            );
        }catch(AuthenticationException e){
            map.put("message", "Bad credentials");
            map.put("status", false);

            return new ResponseEntity<>(map, HttpStatus.UNAUTHORIZED);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);
        List<String> roles = userDetails.getAuthorities().stream().map(
                GrantedAuthority::getAuthority).toList();
        LoginResponse response = new  LoginResponse(userDetails.getUsername(), jwtToken, roles);
        return ResponseEntity.ok(response);
    }
}

package com.example.identity_access_management.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils{
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs = 3;

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            logger.debug("Authorization header: {}",bearerToken);
            return bearerToken.substring(7);
        }
        return null;
    }

//    Generate token from userName
    public String generateTokenFromUsername(UserDetails userDetails){
        String username = userDetails.getUsername();
        return Jwts.builder().subject(username).issuedAt(new Date()).
                expiration(new Date((new Date().getTime()+jwtExpirationMs))).signWith(key()).compact();
    }

//    Getting username from JWT token
    public String getUSernameFromJWTToken(String token){
        return Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(token).getPayload().getSubject();
    }

//    Generate signing key
    public Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

//    Validate jwt token
    public boolean validateJwtToken(String authToken){
        try {
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException m){
            logger.error("Invalid JWT token: {}", m.getMessage());
        }catch (ExpiredJwtException e){
            logger.error("Jwt token is expired: {}", e.getMessage());
        }catch (UnsupportedJwtException u) {
            logger.error("Jwt token is unsupported: {}", u.getMessage());
        }catch(IllegalArgumentException e){
            logger.error("Jwt claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}

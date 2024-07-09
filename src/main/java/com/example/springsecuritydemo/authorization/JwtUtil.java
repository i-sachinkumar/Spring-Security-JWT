package com.example.springsecuritydemo.authorization;

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
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${app.jwt.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwt.jwtExpirationMS}")
    private long jwtExpirationMS;

    public String getJwtFromHeader(HttpServletRequest request){
        logger.info("Entering getJwtFromHeader method");
        String bearerToken = request.getHeader("Authorization");
        logger.info("Bearer token from header: {}", bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            String token = bearerToken.substring(7);
            logger.info("Extracted token: {}", token);
            return token;
        }
        logger.info("No valid bearer token found");
        return null;
    }

    public String generateTokenFromUserName(UserDetails userDetails){
        logger.info("Entering generateTokenFromUserName method for user: {}", userDetails.getUsername());
        String userName = userDetails.getUsername();
        logger.debug("Expiration time: {} ms", jwtExpirationMS);
        String token = Jwts.builder()
                .setSubject(userName)
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpirationMS))
                .signWith(getKey())
                .compact();
        logger.info("Generated token: {}", token);
        return token;
    }

    private Key getKey(){
        logger.info("Entering getKey method");
        logger.debug("Secret: {}", jwtSecret);
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
        logger.info("Generated signing key");
        return key;
    }

    public String getUserNameFromToken(String token){
        logger.info("Entering getUserNameFromToken method with token: {}", token);
        String username = Jwts.parser()
                .verifyWith((SecretKey) getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
        logger.info("Extracted username: {}", username);
        return username;
    }

    public boolean validate(String token){
        logger.info("Entering validate method with token: {}", token);
        try{
            Jwts.parser()
                    .verifyWith((SecretKey) getKey())
                    .build()
                    .parseSignedClaims(token);
            logger.info("Token is valid");
            return true;
        } catch (MalformedJwtException e){
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e){
            logger.error("JWT token expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e){
            logger.error("JWT token unSupported: {}", e.getMessage());
        } catch (IllegalArgumentException e){
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e){
            logger.error("Error occurred: {}", e.getMessage());
        }
        logger.info("Token is not valid");
        return false;
    }

}

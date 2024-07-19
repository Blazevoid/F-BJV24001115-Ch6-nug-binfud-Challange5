package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.account.jwt;

import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.account.UserDetailServiceImpl;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.account.UserDetailsImpl;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private Long expirationTime;

    public String getEmail(String jwt) {
        return Jwts.parserBuilder()
                .setSigningKey(keys())
                .build()
                .parseClaimsJws(jwt)
                .getBody()
                .getSubject();
    }

    private Key keys() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    public String generateToken(Authentication authentication) {
        UserDetailsImpl userDetailService = (UserDetailsImpl) authentication.getPrincipal();

        Date now = new Date();

        return Jwts.builder()
                .setSubject(userDetailService.getUsername())
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expirationTime))
                .signWith(keys(), SignatureAlgorithm.HS256)
                .compact();
    }
}

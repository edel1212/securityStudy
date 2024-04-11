package com.yoo.securityStudy.config;

import com.yoo.securityStudy.dto.MemberDTO;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;

@Log4j2
@Component
public class JwtUtil {
    @Value("jwt.expiration_time")
    private Long accessTokenExpTime;
    @Value("jwt.secret")
    private String secret;

    /**
     * Access Token 생성
     * @param memberDTO
     * @return Access Token String
     */
    public String createAccessToken(MemberDTO memberDTO) {
        return createToken(memberDTO, accessTokenExpTime);
    }

    /**
     * JWT 생성
     * @param memberDTO
     * @param expireTime
     * @return JWT String
     */
    private String createToken(MemberDTO memberDTO, long expireTime) {
        Claims claims = Jwts.claims();
        claims.put("memberId", memberDTO.getId());
        claims.put("role", memberDTO.getRoles());

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime tokenValidity = now.plusSeconds(expireTime);


        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(Instant.now()))
                //.setExpiration(tokenValidity)
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

}

package com.yoo.securityStudy.config;

import com.yoo.securityStudy.dto.MemberDTO;
import io.jsonwebtoken.*;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZonedDateTime;
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
     * JWT 검증
     * - 각각 예외에 따라 ControllerAdvice를 사용해서 처리가 가능함
     * @param accessToken
     * @return IsValidate
     */
    public boolean validateToken(String accessToken) {
        try {
            Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(accessToken);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        } // try - catch
        return false;
    }

    /**
     * JWT Claims 추출
     * @param accessToken
     * @return JWT Claims
     */
    public Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secret)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }// try - catch
    }

    /**
     * Token에서 Member ID 추출
     * @param accessToken
     * @return Member ID
     */
    public String getUserId(String accessToken) {
        return parseClaims(accessToken).get("memberId", String.class);
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

        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime tokenValidity = now.plusSeconds(expireTime);


        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(tokenValidity.toInstant()))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

}

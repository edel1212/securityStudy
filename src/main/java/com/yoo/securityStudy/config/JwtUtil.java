package com.yoo.securityStudy.config;

import com.yoo.securityStudy.dto.JwtLoginDTO;
import com.yoo.securityStudy.security.dto.JwtToken;
import io.jsonwebtoken.*;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.stream.Collectors;

@Log4j2
@Component
public class JwtUtil {
    @Value("${jwt.expiration_time}")
    private Long accessTokenExpTime;
    @Value("${jwt.secret}")
    private String secret;


    //////////////////////////////////////
    /**
     * createAccessToken 이슈로 인해 재생성 중
     *
     * - 👉 Authentication을 통해 로그인한 정보를 받아서 사용이 가능하다!!
     * */
    public JwtToken generateToken(Authentication authentication){
        // 로그인에 성공한 사용자의 권한을 가져온 후 문자열로 반환
        // ex) "ROLE_USER,ROLE_MANAGER,ROLE_ADMIN"
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        // 로그인에 성공한 계정Id
        String userName = authentication.getName();

        // 토큰 만료시간 생성
        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime tokenValidity = now.plusSeconds(this.accessTokenExpTime);

        Claims claims = Jwts.claims();
        claims.put("memberId", userName);
        claims.put("auth", authorities);

        // Jwt AccessToken 생성
        String accessToken =  Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(tokenValidity.toInstant()))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();

        // Refresh Token 생성
        // 토큰 만료시간 생성
        ZonedDateTime reNow = ZonedDateTime.now();
        ZonedDateTime reTokenValidity = reNow.plusSeconds(this.accessTokenExpTime);
        String refreshToken = Jwts.builder()
                .setExpiration(Date.from(reTokenValidity.toInstant()))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();

        return JwtToken.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }



    /////////////////////////////////////

    /**
     * Access Token 생성
     * @param jwtLoginDTO
     * @return Access Token String
     */
    public String createAccessToken(JwtLoginDTO jwtLoginDTO) {
        return createToken(jwtLoginDTO, accessTokenExpTime);
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
    private String createToken(JwtLoginDTO jwtLoginDTO, long expireTime) {
        Claims claims = Jwts.claims();
        claims.put("memberId", jwtLoginDTO.getMemberId());
        claims.put("role", jwtLoginDTO.getRoles());

        // 👉 LocalDateTime과 차이점은 위치 지역대 시간대가 포함되어 있다는 것이다. ( 타임존 설정이 가능함 )
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

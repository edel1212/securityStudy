package com.yoo.securityStudy.config;

import com.yoo.securityStudy.security.dto.JwtToken;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Log4j2
@Component
public class JwtUtil {
    @Value("${jwt.expiration_time}")
    private Long accessTokenExpTime;
    @Value("${jwt.secret}")
    private String secret;

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
        ZonedDateTime reTokenValidity = now.plusSeconds(this.accessTokenExpTime);
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

    /**
     * JWT Token 생성
     * - 이전에 사용하던 Claims 토대로 토큰들 재생성 
     * @param claims
     * @return JwtToken
     */
    public JwtToken generateNewToken(Claims claims){

        // 토큰 만료시간 생성
        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime tokenValidity = now.plusSeconds(this.accessTokenExpTime);

        // Jwt AccessToken 생성
        String accessToken =  Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(tokenValidity.toInstant()))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();

        // Refresh Token 생성
        // 토큰 만료시간 생성
        ZonedDateTime reTokenValidity = now.plusSeconds(this.accessTokenExpTime);
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
     * JWT 값 추출
     * @param request
     * @return String Jwt Token 원문 값
     */
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        if (bearerToken == null || !bearerToken.startsWith("Bearer ")) return null;
        return bearerToken.replaceAll("Bearer ","");
    }


    /**
     * 토큰 값을 통해 Authentication 객체 생성
     *
     * @param accessToken the access token
     * @return the authentication
     */
    public Authentication getAuthentication(String accessToken) {
        // 1 . 토큰에서 Claims 값을 가져온다. - 내가 넣은 값이 들어있음
        Claims claims = this.parseClaims(accessToken);

        // 2 . 주입된 토큰에서 내가 넣은 값의 유무를 체크
        if(claims.get("memberId") == null || claims.get("auth") == null) {
            // 예외 발생 시켜 처리하자
            throw new RuntimeException();
        }// if

        // 3 . claims에서 권한 정보 추출 후 Spring Security의 권한 형식에 맞게 변환
        //   ⭐️ jwt에 등록된 권한은 Security자체에서 주입된 값이기에 ROLE_가 prefix로 붙어있다!
        //      ex) ROLE_ADMIN, ROLE_USER
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
        // 계정ID
        String username = claims.get("memberId").toString();

        // 4 . UserDetail 객체 생성
        UserDetails principal = new User(username, "", authorities);

        // UsernamePasswordAuthenticationToken로 반환 - uerDetail 정보와 권한 추가
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    /**
     * AccessToken 내 Bearer 제거
     *
     * @param AccessToken the access token
     * @return removeBearer
     */
    private String removeBearer(String AccessToken){
        return AccessToken.replaceAll("Bearer ","");
    }
}

package com.yoo.securityStudy.security.filter;

import com.yoo.securityStudy.config.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 1. Request Header 에서 JWT 토큰 추출
        String token = jwtUtil.resolveToken(request);
        // 2. token이 없을 경우 해당 필터 스킵
        if(token == null) filterChain.doFilter(request, response);
        // 3. Token 유효값 검사 - 이상이 있을 경우 Exception Handler 적용
        jwtUtil.validateToken(token);

        try {
            // 토큰이 유효할 경우 토큰에서 Authentication 객체를 가지고 와서 SecurityContext 에 저장
            Authentication authentication = jwtUtil.getAuthentication(token);

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e){
            e.printStackTrace();
        }
        filterChain.doFilter(request, response);
    }
}
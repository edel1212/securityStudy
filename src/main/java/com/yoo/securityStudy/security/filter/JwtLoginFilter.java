package com.yoo.securityStudy.security.filter;

import com.yoo.securityStudy.config.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;

public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {

    private JwtUtil jwtUtil;

    public JwtLoginFilter(String defaultFilterProcessesUrl, JwtUtil jwtUtil) {
        super(defaultFilterProcessesUrl); // 👉 여기에 입력되는것이 login path이다
        this.jwtUtil = jwtUtil;
    }

    // 인증 처리
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String email = request.getParameter("아이디 파라미터명");
        String pw    = request.getParameter("패스워드 파라미터명");
        return null;
    }

    // 성공 시
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // 아래의 정보를 통해 성공 로직을 채울 수 있음
        authResult.getAuthorities();
        authResult.getPrincipal();
        super.successfulAuthentication(request, response, chain, authResult);
    }

    // 실패 시
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        // TODO Fail 시 설정
        super.unsuccessfulAuthentication(request, response, failed);
    }

}

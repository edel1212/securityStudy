package com.yoo.securityStudy.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yoo.securityStudy.exception.dto.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Log4j2
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.info("- Custom Authentication Entry PointHandler 접근 -");
        log.info("----------------------------");
        log.info(authException);
        // - 그냥 접근
        // org.springframework.security.authentication.InsufficientAuthenticationException: Full authentication is required to access this resource
        // - 비밀번호 틀렸을 경우
        log.info("----------------------------");
        var objectMapper = new ObjectMapper();
        int scUnauthorized = HttpServletResponse.SC_UNAUTHORIZED;
        response.setStatus(scUnauthorized);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        ErrorResponse errorResponse = ErrorResponse.builder()
                .code(scUnauthorized)
                .message(authException.getMessage())
                .build();
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}

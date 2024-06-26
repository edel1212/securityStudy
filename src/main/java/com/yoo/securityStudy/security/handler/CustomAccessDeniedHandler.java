package com.yoo.securityStudy.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yoo.securityStudy.exception.dto.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Log4j2
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
       log.info("- Custom Access Denied Handler 접근 -");
        var objectMapper = new ObjectMapper();
        int scUnauthorized = HttpServletResponse.SC_UNAUTHORIZED;
        response.setStatus(scUnauthorized);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        ErrorResponse errorResponse = ErrorResponse.builder()
                .code(scUnauthorized)
                .message("접근 권한이 없습니다.")
                .build();
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}

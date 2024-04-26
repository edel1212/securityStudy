package com.yoo.securityStudy.exception.controller;

import com.yoo.securityStudy.exception.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Log4j2
public class ExceptionController {
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity badCredentialsException(BadCredentialsException e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .code(HttpServletResponse.SC_UNAUTHORIZED)
                .message("아이디와 비밀번호를 확인해주세요.")
                .build();
        log.error("----------------------");
        log.info(e.getMessage());
        log.error("----------------------");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }
}

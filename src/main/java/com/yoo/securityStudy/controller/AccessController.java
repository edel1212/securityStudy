package com.yoo.securityStudy.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Log4j2
@RequiredArgsConstructor
@RestController
public class AccessController {


    @GetMapping("/all")
    @PreAuthorize("permitAll()")  // 👍 권한이 있는 모두가 접근 가능
    public ResponseEntity allAccess(){
        return ResponseEntity.ok("All - Member Access!!");
    }

    @GetMapping("/user")
    public ResponseEntity userAccess(){
        return ResponseEntity.ok("User Access!!");
    }

    @GetMapping("/manager")
    // 👍 다양한 조건문을 사용 가능하다.
    // @PreAuthorize("isAuthenticated() and (( returnObject.name == principal.name ) or hasRole('ROLE_ADMIN'))")
    @PreAuthorize("hasRole('ROLE_MANAGER')")
    public ResponseEntity managerAccess(Authentication authentication){
        log.info("-----------------------------");
        authentication.getAuthorities().stream().forEach(log::info);
        log.info("-----------------------------");
        return ResponseEntity.ok("manager Access!!");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public ResponseEntity adminAccess(Authentication authentication){
        log.info("-----------------------------");
        authentication.getAuthorities().stream().forEach(log::info);
        log.info("-----------------------------");
        return ResponseEntity.ok("admin Access!!");
    }
}

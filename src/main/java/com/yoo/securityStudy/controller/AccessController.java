package com.yoo.securityStudy.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccessController {

    @GetMapping("/all")
    public ResponseEntity allAccess(){
        return ResponseEntity.ok("All - Member Access!!");
    }

    @GetMapping("/user")
    public ResponseEntity userAccess(){
        return ResponseEntity.ok("User Access!!");
    }

    @GetMapping("/manager")
    public ResponseEntity managerAccess(){
        return ResponseEntity.ok("manager Access!!");
    }

    @GetMapping("/admin")
    public ResponseEntity adminAccess(){
        return ResponseEntity.ok("admin Access!!");
    }
}

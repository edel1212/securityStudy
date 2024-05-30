package com.yoo.securityStudy.controller;

import com.yoo.securityStudy.dto.social.GetSocialOAuthRes;
import com.yoo.securityStudy.social.OAuthService;
import com.yoo.securityStudy.social.SocialType;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@Log4j2
@RequestMapping("/app/accounts")
public class SocialController {

    private final OAuthService oAuthService;

    @GetMapping("/auth/{type}")
    public void socialLoginRedirect(@PathVariable String type) throws IOException {
        log.info("-----------");
        log.info("socialType :::" + type);
        log.info("-----------");
        oAuthService.request(type);
    }

    @ResponseBody
    @GetMapping(value = "/auth/{socialType}/callback")
    public ResponseEntity<GetSocialOAuthRes> callback ( @PathVariable String type
            , @RequestParam String code) throws Exception{
        log.info(">> 소셜 로그인 API 서버로부터 받은 code :"+ code);
        return ResponseEntity.ok(oAuthService.oAuthLogin(type, code));
    }

}

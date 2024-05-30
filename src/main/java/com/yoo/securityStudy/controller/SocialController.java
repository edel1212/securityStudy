package com.yoo.securityStudy.controller;

import com.yoo.securityStudy.dto.social.GetSocialOAuthRes;
import com.yoo.securityStudy.social.Constant;
import com.yoo.securityStudy.social.OAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@CrossOrigin("*")
@RequestMapping("/app/accounts")
public class SocialController {

    private final OAuthService oAuthService;

    @GetMapping("/auth/{socialLoginType}")
    public void socialLoginRedirect(@PathVariable(name="socialLoginType") String SocialLoginPath) throws IOException {
        Constant.SocialLoginType socialLoginType= Constant.SocialLoginType.valueOf(SocialLoginPath.toUpperCase());
        oAuthService.request(socialLoginType);
    }

    @ResponseBody
    @GetMapping(value = "/auth/{socialLoginPath}/callback")
    public ResponseEntity<GetSocialOAuthRes> callback ( @PathVariable String socialLoginPath
                                                      , @RequestParam String code) throws Exception{
        System.out.println(">> 소셜 로그인 API 서버로부터 받은 code :"+ code);
        Constant.SocialLoginType socialLoginType = Constant.SocialLoginType.valueOf(socialLoginPath.toUpperCase());
        return ResponseEntity.ok(oAuthService.oAuthLogin(socialLoginType, code));
    }

}

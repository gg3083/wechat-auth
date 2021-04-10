package com.work.wechat;

import com.work.wechat.util.IPUtils;
import com.work.wechat.util.WechatSHA1;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Objects;

@SpringBootApplication
@RestController
@Slf4j
public class WechatAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(WechatAuthApplication.class, args);
    }

    final String TOKEN = "tokenwechat";

    @GetMapping("/")
    public String index(HttpServletRequest request) {
        String ip = IPUtils.getIpAddr(request);
        log.info("当前访问ip {} ", ip);
        return ip;
    }

    @GetMapping("/checkToken")
    public String checkToken(HttpServletRequest request) {
        String signature = request.getParameter("signature");
        String timestamp = request.getParameter("timestamp");
        String nonce = request.getParameter("nonce");
        String echostr = request.getParameter("echostr");
        String token = TOKEN;
        log.info("signature:{} timestamp: {} nonce:{} token:{} echostr:{}", signature, timestamp, nonce, token, echostr);
        if (StringUtils.isEmpty(signature) || StringUtils.isEmpty(timestamp) || StringUtils.isEmpty(nonce)) {
            return "fail";
        }
        String sign = WechatSHA1.getSHA1(token, timestamp, nonce);
        log.info("加密后的签名为{}", sign);
        return Objects.equals(sign, signature) ? echostr : "fail";

    }


}

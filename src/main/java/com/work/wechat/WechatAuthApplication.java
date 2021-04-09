package com.work.wechat;

import com.work.wechat.util.WechatSHA1;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

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
        String ip = this.getIP(request);
        log.info("当前访问ip {} ", ip);
        return "/" + ip;
    }

    @GetMapping("/checkToken")
    public String checkToken(HttpServletRequest request) {
        String signature = request.getParameter("signature");
        String timestamp = request.getParameter("timestamp");
        String nonce = request.getParameter("nonce");
        String token = TOKEN;
        if (StringUtils.isEmpty(signature) || StringUtils.isEmpty(timestamp) || StringUtils.isEmpty(nonce)  ){
            return "fail";
        }
        String sign = WechatSHA1.getSHA1(token, timestamp, nonce);
        return sign == signature ? token : "fail";

    }

    public String getIP(HttpServletRequest request) {
        String ip = request.getHeader("x-forwarded-for");
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

}

package com.work.wechat;

import com.alibaba.fastjson.JSONObject;
import com.work.wechat.util.IPUtils;
import com.work.wechat.util.WechatSHA1;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpEntity;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@SpringBootApplication
@RestController
@Slf4j
public class WechatAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(WechatAuthApplication.class, args);
    }

    final String TOKEN = "tokenwechat";
    final String APPID = "wxcfcde17bbba4a03d";
    final String SECRET = "151b5f121ef55723209bedb1e8d8ccd5";


    @Autowired
    private RestTemplate restTemplate;

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

    @GetMapping("/callback")
    public void callback(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String code = request.getParameter("code");
        String state = request.getParameter("state");
        log.info("code:{} state: {}", code, state);
        if (StringUtils.isEmpty(code) || StringUtils.isEmpty(state)) {
            response.sendRedirect("http://www.401.com");
        }
        String url = String.format(
                "https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
                APPID, SECRET, code);
        String s = restTemplate.getForObject(url, String.class);
        System.err.println(s);
        JSONObject jsonObject = JSONObject.parseObject(s);
        log.info("回调响应为: {}", jsonObject.toJSONString());
        String accessToken = jsonObject.getString("access_token");
        if (StringUtils.isEmpty(accessToken) ) {
            response.sendRedirect("http://www.502.com");

        }
        String openId = jsonObject.getString("openid");

        //todo 根据openid查询数据库 直接使用老数据


        String getUserInfoUrl = String.format(
                "https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s&lang=zh_CN",
                accessToken, openId);
        String str = restTemplate.getForObject(getUserInfoUrl, String.class);
        System.err.println(str);
        JSONObject res = JSONObject.parseObject(str);
        log.info("获取用户信息响应: {}", res.toJSONString());
        //TODO 写入数据库
        response.sendRedirect("http://www.success.com");
    }

}

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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 微信网页授权流程
 * 文档地址：https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#0
 * 业务流程
 * - 引导用户点击某个界面按钮（界面显示：该界面由XX公司开发，需要授权获取用户昵称、头像权限）
 * 请求接口：GET https://open.weixin.qq.com/connect/oauth2/authorize?
 *          appid=wx36f3c1d1a81f7421
 *          &redirect_uri=https://go.3083.work/wechat/callback #回调接口，会根据此接口获取信息
 *          &response_type=code
 *          &scope=snsapi_userinfo
 *          &state=自定义信息
 *          #wechat_redirect
 *
 * - 回调接口（自己写的代码） /wechat/callback
 *  回调接口流程：
 *  - 会接收两个参数
 *  ```
 *         String code = request.getParameter("code");
 *         String state = request.getParameter("state");
 *  ```
 *  - 获取token code参数为下方请求token使用，state为自定义参数，接收上一步传过来的自定义信息
 * 请求接口：GET   https://api.weixin.qq.com/sns/oauth2/access_token?appid=APPID&secret=SECRET&code=CODE&grant_type=authorization_code
 *  响应：
 *      {
 *          "access_token":"ACCESS_TOKEN",
 *          "expires_in":7200,
 *          "refresh_token":"REFRESH_TOKEN",
 *          "openid":"OPENID",
 *          "scope":"SCOPE"
 *      }
 * - 拉取用户信息
 * 请求接口：GET  https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN&openid=OPENID&lang=zh_CN
 *  响应：
 *      {
 *          "openid": "OPENID",
 *          "nickname": NICKNAME,
 *          "sex": 1,
 *          "province":"PROVINCE",
 *          "city":"CITY",
 *          "country":"COUNTRY",
 *          "headimgurl":"https://thirdwx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/46",
 *          "privilege":[ "PRIVILEGE1" "PRIVILEGE2"     ],
 *          "unionid": "o6_bmasdasdsad6_2sgVt7hMZOPfL"
 *      }
 * - 省略：刷新token，检验token，失败情况下的错误处理！
 */
@SpringBootApplication
@RestController
@Slf4j
public class WechatAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(WechatAuthApplication.class, args);
    }

    final String TOKEN = "wechat_public_account_token";
    final String APPID = "wx36f3c1d1a81f7421";
    final String SECRET = "44c5029a5021b3e03a13a0ffdb7a5019";


    @Autowired
    private RestTemplate restTemplate;

    @RequestMapping("/")
    public String index(HttpServletRequest request) {
        String ip = IPUtils.getIpAddr(request);
        log.info("当前访问ip {} ", ip);
        return ip;
    }

    @RequestMapping("/checkToken")
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

    @RequestMapping("/callback")
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
        JSONObject jsonObject = JSONObject.parseObject(s);
        log.info("回调响应为: {}", jsonObject.toJSONString());
        String accessToken = jsonObject.getString("access_token");
        if (StringUtils.isEmpty(accessToken) ) {
            response.sendRedirect("https://baidu.com");

        }
        String openId = jsonObject.getString("openid");

        //todo 根据openid查询数据库 直接使用老数据


        String getUserInfoUrl = String.format(
                "https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s&lang=zh_CN",
                accessToken, openId);
        String str = restTemplate.getForObject(getUserInfoUrl, String.class);
        JSONObject res = JSONObject.parseObject(str);
        log.info("获取用户信息响应: {}", res.toJSONString());
        //TODO 写入数据库
        response.sendRedirect("https://go.3083.work/wechat_1/");
    }

}

package com.andaily.springoauth.web;

import com.andaily.springoauth.service.OauthService;
import com.andaily.springoauth.service.dto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

/**
 * Handle 'authorization_code'  type actions
 *
 * @author Shengzhao Li
 */
@Controller
public class AuthorizationCodeController {


    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationCodeController.class);


    @Value("#{properties['user-authorization-uri']}")
    private String userAuthorizationUri;


    @Value("#{properties['application-host']}")
    private String host;


    @Value("#{properties['unityUserInfoUri']}")
    private String unityUserInfoUri;


    @Autowired
    private OauthService oauthService;


    /*
   * Auto - Entrance
   * */
    @RequestMapping(value = "authorization_code_auto", method = RequestMethod.GET)
    public void authorizationCodeAuto(HttpServletRequest request, HttpServletResponse response) throws IOException {

        Cookie accessToken = WebUtils.getCookie(request, "access_token");
        Cookie refreshToken = WebUtils.getCookie(request, "refresh_token");

        if (accessToken != null) {
            //直接请求
            response.sendRedirect(host + "unity_user_info?access_token=" + accessToken.getValue());
            return;
        }

        if (refreshToken != null) {
            //更新token
            //to do list...
        }

        AuthorizationCodeDto dto = new AuthorizationCodeDto();
        dto.setClientId("unity-client");
        dto.setResponseType("code");
        dto.setScope("read write");
        dto.setRedirectUri(host + "authorization_code_callback_auto");
        dto.setState(UUID.randomUUID().toString());
        dto.setUserAuthorizationUri(userAuthorizationUri);
        final String fullUri = dto.getFullUri();
        WebUtils.saveState(request, dto.getState());
        response.sendRedirect(fullUri);
    }

    /*
   * Entrance:   step-1
   * */
    @RequestMapping(value = "authorization_code", method = RequestMethod.GET)
    public String authorizationCode(Model model) {
        model.addAttribute("userAuthorizationUri", userAuthorizationUri);
        model.addAttribute("host", host);
        model.addAttribute("unityUserInfoUri", unityUserInfoUri);
        model.addAttribute("state", UUID.randomUUID().toString());
        return "authorization_code";
    }


    /*
   * Save state firstly
   * Redirect to oauth-server login page:   step-2
   * */
    @RequestMapping(value = "authorization_code", method = RequestMethod.POST)
    public String submitAuthorizationCode(AuthorizationCodeDto codeDto, HttpServletRequest request) throws Exception {
        //save stats  firstly
        WebUtils.saveState(request, codeDto.getState());

        final String fullUri = codeDto.getFullUri();
        LOG.debug("Redirect to Oauth-Server URL: {}", fullUri);
        return "redirect:" + fullUri;
    }


    /*
   * Oauth callback (redirectUri):   step-3
   *
   * Handle 'code', go to 'access_token' ,validation oauth-server response data
   *
   *  authorization_code_callback
   * */
    @RequestMapping(value = "authorization_code_callback")
    public String authorizationCodeCallback(AuthCallbackDto callbackDto, HttpServletRequest request, Model model) throws Exception {

        if (callbackDto.error()) {
            //Server response error
            model.addAttribute("message", callbackDto.getError_description());
            model.addAttribute("error", callbackDto.getError());
            return "redirect:oauth_error";
        } else if (correctState(callbackDto, request)) {
            //Go to retrieve access_token form
            AuthAccessTokenDto accessTokenDto = oauthService.createAuthAccessTokenDto(callbackDto);
            model.addAttribute("accessTokenDto", accessTokenDto);
            model.addAttribute("host", host);
            return "code_access_token";
        } else {
            //illegal state
            model.addAttribute("message", "Illegal \"state\": " + callbackDto.getState());
            model.addAttribute("error", "Invalid state");
            return "redirect:oauth_error";
        }

    }


    @RequestMapping(value = "authorization_code_callback_auto")
    @ResponseBody
    public String authorizationCodeCallbackAuto(AuthCallbackDto callbackDto, HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {

        if (callbackDto.error()) {
            return callbackDto.toString();
        }
        if (correctState(callbackDto, request)) {
            AuthAccessTokenDto authAccessTokenDto = oauthService.createAuthAccessTokenDto(callbackDto);
            authAccessTokenDto.setClientId("unity-client");
            authAccessTokenDto.setClientSecret("unity");
            authAccessTokenDto.setRedirectUri(host + "authorization_code_callback_auto");
            //用code换access_token
            AccessTokenDto accessTokenDto = oauthService.retrieveAccessTokenDto(authAccessTokenDto);
            if (!StringUtils.isEmpty(accessTokenDto.getAccessToken())) {
                //将获得的token/refresh_token写入cookie,下次可直接使用
                WebUtils.writeCookieWithSeconds(response, "access_token", accessTokenDto.getAccessToken(), accessTokenDto.getExpiresIn() - 5);
                WebUtils.writeCookieWithSeconds(response, "refresh_token", accessTokenDto.getRefreshToken(), accessTokenDto.getExpiresIn());

//                //用access_token去访问受保护的资源
//                UserDto userDto = oauthService.loadUnityUserDto(accessTokenDto.getAccessToken());
//                return userDto.toString();

                response.sendRedirect(host + "unity_user_info?access_token=" + accessTokenDto.getAccessToken());
                return null;
            }
        }

        return callbackDto.toString();
    }


    /**
     * Use HttpClient to get access_token :   step-4
     * <p/>
     * Then, 'authorization_code' flow is finished,  use 'access_token'  visit resources now
     *
     * @param tokenDto AuthAccessTokenDto
     * @param model    Model
     * @return View
     * @throws Exception
     */
    @RequestMapping(value = "code_access_token", method = RequestMethod.POST)
    public String codeAccessToken(AuthAccessTokenDto tokenDto, Model model) throws Exception {
        final AccessTokenDto accessTokenDto = oauthService.retrieveAccessTokenDto(tokenDto);
        if (accessTokenDto.error()) {
            model.addAttribute("message", accessTokenDto.getErrorDescription());
            model.addAttribute("error", accessTokenDto.getError());
            return "oauth_error";
        } else {
            model.addAttribute("accessTokenDto", accessTokenDto);
            model.addAttribute("unityUserInfoUri", unityUserInfoUri);
            return "access_token_result";
        }
    }


    /*
     * Check the state is correct or not after redirect from Oauth Server.
     */
    private boolean correctState(AuthCallbackDto callbackDto, HttpServletRequest request) {
        final String state = callbackDto.getState();
        return WebUtils.validateState(request, state);
    }

}
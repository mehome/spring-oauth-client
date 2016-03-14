package com.andaily.springoauth.web;

import net.sf.json.JSON;
import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * @author Shengzhao Li
 */
public abstract class WebUtils {


    private WebUtils() {
    }


    /*
     *  Save state to ServletContext, key = value = state
     */
    public static void saveState(HttpServletRequest request, String state) {
        final ServletContext servletContext = request.getSession().getServletContext();
        servletContext.setAttribute(state, state);
    }

    /*
     *  Validate state when callback from Oauth Server.
     *  If validation successful, will remove it from ServletContext.
     */
    public static boolean validateState(HttpServletRequest request, String state) {
        if (StringUtils.isEmpty(state)) {
            return false;
        }
        final ServletContext servletContext = request.getSession().getServletContext();
        final Object value = servletContext.getAttribute(state);

        if (value != null) {
            servletContext.removeAttribute(state);
            return true;
        }
        return false;
    }


    public static void writeJson(HttpServletResponse response, JSON json) {
        response.setContentType("application/json;charset=UTF-8");
        try {
            PrintWriter writer = response.getWriter();
            json.write(writer);
            writer.flush();
        } catch (IOException e) {
            throw new IllegalStateException("Write json to response error", e);
        }

    }


    static final String cookiePath = "/";

    /**
     * 写入Cookie
     *
     * @param key
     * @param value
     * @param expiredMinute
     */
    public static void writeCookie(HttpServletResponse response, String key,
                                   String value, Integer expiredMinute) {
        Cookie cookie;
        try {
            if (!StringUtils.isEmpty(value)) {
                value = URLEncoder.encode(value, "UTF-8");
            }
            cookie = new Cookie(key, value);
            cookie.setPath(cookiePath);
            if (expiredMinute != null) {
                cookie.setMaxAge(expiredMinute * 60);
            }
            response.addCookie(cookie);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static void writeCookieWithSeconds(HttpServletResponse response, String key,
                                   String value, Integer expiredSeconds) {
        Cookie cookie;
        try {
            if (!StringUtils.isEmpty(value)) {
                value = URLEncoder.encode(value, "UTF-8");
            }
            cookie = new Cookie(key, value);
            cookie.setPath(cookiePath);
            if (expiredSeconds != null) {
                cookie.setMaxAge(expiredSeconds);
            }
            response.addCookie(cookie);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static void writeCookie(HttpServletResponse response, String key,
                                   String value) {
        writeCookie(response, key, value, null);
    }

    /**
     * 读Cookie
     *
     * @param request
     * @param key
     * @return
     */
    public static Cookie getCookie(HttpServletRequest request, String key) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie c : cookies) {
            if (c.getName().equals(key)) {
                return c;
            }
        }
        return null;
    }

    /**
     * 读Cookie的值
     *
     * @param request
     * @param key
     * @return
     */
    public static String getCookieValue(HttpServletRequest request, String key) {
        Cookie cookie = getCookie(request, key);
        if (cookie != null) {
            try {
                return URLDecoder.decode(cookie.getValue(), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /**
     * 删除Cookie
     *
     * @param response
     * @param key
     */
    public static void deleteCookie(HttpServletResponse response, String key) {
        writeCookie(response, key, null, 0);

    }

}
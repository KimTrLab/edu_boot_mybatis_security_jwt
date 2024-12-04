package com.kimtr.web.jwt;

import java.io.IOException;
import java.util.Iterator;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;


@Controller
//@RequestMapping("/api")
public class JwtAuthenticateController {
	private final JwtTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;

    public JwtAuthenticateController(JwtTokenProvider tokenProvider, AuthenticationManager authenticationManager) {
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
    }
    @PostMapping("/authenticate")
    public String authorize(@RequestParam("id") String username, @RequestParam("pass") String password, HttpServletResponse response) throws IOException {
    	System.out.println(username+"이 토큰생성쪽으로 들어옴");
    	//UserDetails 에서 유저 정보 가져옴
    	 UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
         //인가
    	 Authentication authentication = authenticationManager.authenticate(authenticationToken);
    	// SecurityContext 에 Authentication 객체를 저장합니다
         SecurityContextHolder.getContext().setAuthentication(authentication);
         
         // 4. JWT 생성
      //   Iterator<? extends GrantedAuthority> iterator = authentication.getAuthorities().iterator();
      //   String jwt = tokenProvider.createToken(username,iterator.next().getAuthority());
         String jwt = tokenProvider.createToken(username,authentication);
         System.out.println("생성된 토큰은"+jwt);
      //   response.setHeader("Authorization", "Bearer"+jwt);
         Cookie cookie = new Cookie("token", "Bearer:"+jwt);
         cookie.setAttribute("username", username);
         cookie.setMaxAge(60 * 60);  // 쿠키 유효 시간 : 1시간
         response.addCookie(cookie);
      //   response.addHeader("Access-Control-Expose-Headers", "Authorization, Refresh");
    	return "home";
    }

}

package com.kimtr.web.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import io.jsonwebtoken.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

//spring filter > JwtAuthenticationFilter > 
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {

	private final JwtTokenProvider jwtTokenProvider;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException, java.io.IOException {
		
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = jwtTokenProvider.resolveToken(httpServletRequest);  // request객체 정보로 토큰값만 가져오기
        String requestURI = httpServletRequest.getRequestURI();
		// 유효한 토큰인지 확인합니다.
		//System.out.println(token + "유효토큰 확인");
		
		if (token != null && jwtTokenProvider.validateToken(token)) {  // 토큰의 유효성과 만료날짜 확인 
			//System.out.println("유효토큰");
			Authentication authentication = jwtTokenProvider.getAuthentication(token);  // 토큰의 포함 된 인증 데이터(유저정보) 가져오기
			// SecurityContext 에 Authentication 객체를 저장합니다.
			SecurityContextHolder.getContext().setAuthentication(authentication);
			//System.out.println("save");
		}
		
		//System.out.println(requestURI);
		chain.doFilter(request, response);
	}
	
}

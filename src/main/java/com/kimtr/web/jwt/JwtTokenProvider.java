package com.kimtr.web.jwt;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

//토큰을 생성하고 검증하는 클래스입니다.
//해당 컴포넌트는 필터클래스에서 사전 검증을 거칩니다.
@RequiredArgsConstructor
@Component
public class JwtTokenProvider implements InitializingBean {
	private String secretKey = "rkGU45258GGhiolLO2465TFY5345kGU45258GGhiolLO2465TFY5345";
	private Key key;
	private final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

	// 토큰 유효시간 30분
	private long tokenValidTime = 30 * 60 * 1000L;

	// 토큰을 생성
    public String createToken(String username, Authentication authentication) {
    	
    	String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = new Date().getTime();
        Date validity = new Date(now+tokenValidTime);

        return Jwts.builder()
                .claim("username",username)
                .claim("role",authorities)
                .signWith(key, SignatureAlgorithm.HS256)
                .setExpiration(validity)
                .compact();
    }

	// JWT 토큰에서 인증 정보 조회
	public Authentication getAuthentication(String token) {
		//System.out.println(token +"--------------------------------------------");
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        //System.out.println(claims.toString());
       // System.out.println(claims.get("role").toString());
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("role").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
       // System.out.println(claims.getSubject());
       // System.out.println(authorities.toString());
        User principal = new User(claims.get("username").toString(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
	}

	// Request의 Header 또는 쿠키에서 token 값을 가져옵니다. 최신수정 : 쿠키에서 가져오는 걸로
	public String resolveToken(HttpServletRequest request) {
	//return request.getHeader("Authorization");
		//header에서 가져오고 ------------------------------
		/*
		 String bearerToken = request.getHeader("Authorization");
		 if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);        // Bearer 이후의 값을 꺼내감
         }
		 */		
		//header에서 가져오는 법 끝 -----------------------------------
		
		//쿠키에서 가져와 보자
		String bearerToken=null;
		Cookie[] list = request.getCookies();
		if(list !=null) {
			for(Cookie cookie:list) {
				if(cookie.getName().equals("token")) {
					bearerToken = cookie.getValue();
				}
			}
			if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer:")) {  //쿠키형식 때문에 바꿈
				return bearerToken.substring(7);       
			}
		}
        return null;
	}

	// 토큰의 유효성 + 만료일자 확인
	public boolean validateToken(String jwtToken) {
		 try{
	            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwtToken);
	            return true;
	        } catch (io.jsonwebtoken.security.SignatureException | MalformedJwtException e) {
	            logger.info("잘못된 JWT 입니다.");
	        } catch (ExpiredJwtException e){
	            logger.info("만료된 JWT 토큰입니다.");
	        } catch (UnsupportedJwtException e){
	            logger.info("지원 JWT 토큰입니다.");
	        } catch (IllegalArgumentException e){
	            logger.info("JWT 토큰이 잘못되었습니다.");
	        }
	        return false;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		// TODO Auto-generated method stub'
		//secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
		
		byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
	}
}

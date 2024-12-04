package com.kimtr.web.security_config;

import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class authenticationProvider implements AuthenticationProvider {

	
	// https://jaykaybaek.tistory.com/27
	
    @Autowired
    private UserDetailsService userDetailsService;

    private BCryptPasswordEncoder passwordEncoder;

    public authenticationProvider(BCryptPasswordEncoder passwordEncoder){
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
//        System.out.println(username+"/"+password);

        User userDetails = (User)userDetailsService.loadUserByUsername(username);
//        System.out.println(userDetails.getUsername()+"/"+userDetails.getPassword());
        System.out.println("AuthenticationProvider");
        System.out.println(password+"(사용자 입력값)/"+userDetails.getPassword()+"(데이터저장값)/"+passwordEncoder.matches(password, userDetails.getPassword()));
        if(passwordEncoder.matches(password, userDetails.getPassword())==false) {
            throw new BadCredentialsException("Bad credentials");
        }

       // List<GrantedAuthority> authorities = new ArrayList<>();
      //  authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        
        Collection<GrantedAuthority> authorities=userDetails.getAuthorities();

        System.out.println(authorities.toString());

//        return new UsernamePasswordAuthenticationToken(userDetails.getUsername(),userDetails.getPassword(),userDetails.getAuthorities());
        return new UsernamePasswordAuthenticationToken(userDetails,authentication.getCredentials(),authorities);

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}

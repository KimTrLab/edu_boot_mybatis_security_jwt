package com.kimtr.web.security_config;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.kimtr.web.repository.IF_MemberDao;
import com.kimtr.web.vo.MemberVO;

import lombok.RequiredArgsConstructor;


@RequiredArgsConstructor
@Service
public class MyUserDetailsService implements UserDetailsService {
	
	//@Autowired
	private final IF_MemberDao memberdao;
/**
 * UserDetailService에서는 클라이언트에게 받은 username을 검색합니다. 해당 인터페이스에는 loadUserByUsername() 메소드만 정의되어 있습니다.
 * 
 * UserDatailsManager는 UserDetailsService를 상속 받은 인터페이스입니다. 해당 인터페이스는 User의 생성, 업데이트, 삭제 등등 기능을 제공합니다.
public interface UserDetailsManager extends UserDetailsService {

	void createUser(UserDetails user);

	void updateUser(UserDetails user);

	void deleteUser(String username);

	void changePassword(String oldPassword, String newPassword);

	boolean userExists(String username);
}


 * 
 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		try {
			System.out.println("DB값 가져오기"+username);
			MemberVO member = memberdao.selectOne(username);
			System.out.println(member +"님 로그인 시도");
			//return User.builder().username(member.getId()).password(member.getPass()).roles(member.getRole()).build();  // 권한 1개
			return User.builder().username(member.getId()).password(member.getPass()).roles(member.getRole(),"ADMIN").build(); //권한 2개
			// roles 메서드가 자동으로 Collection<GrantedAuthority> 타입으로 변경해 주는 것 같네.. 확신 90%
			// 아래 코드는 3번째 매개변수에서 타입에러 뜸.. 
			//return new User(member.getId(),member.getPass(), member.getRole());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
/*
 * 
UserDetailsService 란?
Spring Security에서 유저의 정보를 가져오는 인터페이스이다.
Spring Security에서 유저의 정보를 불러오기 위해서 구현해야하는 인터페이스로 기본 오버라이드 메서드는 **
@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
 */


package edu.pnu.service;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import edu.pnu.domain.Member;

@Service
public class LoginService {
	@Autowired
	private AuthenticationConfiguration authenticationConfiguration;
	
	@Autowired
	PasswordEncoder encoder;
	
	public String loginProc(Member member) throws Exception {
		
		Authentication authToken = new UsernamePasswordAuthenticationToken(member.getUsername(), member.getPassword());
		
		AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
		
		Authentication auth = authenticationManager.authenticate(authToken);
		
		System.out.println("auth : " + auth);
		
		// 토큰 만들기
		String token = JWT.create()
				.withExpiresAt(new Date(System.currentTimeMillis()+1000*60*10))
				.withClaim("username", member.getUsername())
				.sign(Algorithm.HMAC256("edu.pnu.jwt"));
		
		return "Bearer " + token;
	}
}

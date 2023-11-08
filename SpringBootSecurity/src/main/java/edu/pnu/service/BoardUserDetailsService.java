package edu.pnu.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import edu.pnu.domain.Member;
import edu.pnu.persistence.MemberRepository;

@Service
public class BoardUserDetailsService implements UserDetailsService {
	
	@Autowired
	private MemberRepository memRepo;
	
	@Autowired
	private PasswordEncoder encoder;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		Optional<Member> option = memRepo.findById(username);
		if (!option.isPresent()) {
			throw new UsernameNotFoundException("사용자가 없습니다.");
		}
		
		
		Member member = option.get();
		System.out.println(member);
		
		System.out.println(encoder.matches("abcd", member.getPassword()));
		
		return new User(member.getUsername(), member.getPassword(), AuthorityUtils.createAuthorityList(member.getRole().toString()));
	}

}

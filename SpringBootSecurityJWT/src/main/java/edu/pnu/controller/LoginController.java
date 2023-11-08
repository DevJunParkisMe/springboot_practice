package edu.pnu.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import edu.pnu.domain.Member;
import edu.pnu.service.LoginService;

@RestController
public class LoginController {
	@Autowired
	private LoginService loginService;
	
	@PostMapping("/login")
	public ResponseEntity<?> loginProc(@RequestBody Member member) {
		try {
			String token = loginService.loginProc(member);
			return ResponseEntity.ok()
									.header(HttpHeaders.AUTHORIZATION, token)
									.body("ok");
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
									.body(e.getMessage());
		}
	}
}

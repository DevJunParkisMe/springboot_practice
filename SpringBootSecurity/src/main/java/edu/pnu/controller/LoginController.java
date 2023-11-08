package edu.pnu.controller;

import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class LoginController {
	
	@Autowired
	private PasswordEncoder encoder;
	
	@GetMapping("/login")
	public void login() {}
	
	@GetMapping("/loginSuccess")
	public void loginSuccess() {}
	
	@GetMapping("/auth")
	public @ResponseBody String auth(@AuthenticationPrincipal User user) {		
		return user.toString();
	}
}

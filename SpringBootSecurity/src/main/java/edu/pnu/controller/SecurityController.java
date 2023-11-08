package edu.pnu.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SecurityController {
	
	@GetMapping({"/", "/index"})
	public String index() {
		System.out.println("index 페이지 요청입니다.");
		return "index";
	}
	
	@GetMapping("/member")
	public void member() {
		System.out.println("Member 요청입니다.");
	}

	@GetMapping("/manager")
	public void manager() {
		System.out.println("Manager 요청입니다.");
	}
	
	@GetMapping("/admin")
	public void admin() {
		System.out.println("Admin 요청입니다.");
	}
	
	@GetMapping("/accessDenied")
	public void accessDenied() {}
	
}

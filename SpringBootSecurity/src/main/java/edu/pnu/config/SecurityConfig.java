package edu.pnu.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests(security -> security
				.requestMatchers(new AntPathRequestMatcher("/member/**")).authenticated()
				.requestMatchers(new AntPathRequestMatcher("/manager/**")).hasRole("MANAGER")
				.requestMatchers(new AntPathRequestMatcher("/admin/**")).hasRole("ADMIN")
				.anyRequest().permitAll());
		
		http.csrf(cf -> cf.disable());  // CSRF 보호 비활성화(JavaScript 호출)
		
		http.formLogin(form -> form
					.loginPage("/login")
					.defaultSuccessUrl("/loginSuccess", true)
					);
		
		http.exceptionHandling(ex -> ex.accessDeniedPage("/accessDenied"));
		
		http.logout(logout -> logout
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID")
				.logoutSuccessUrl("/login"));
		
		
		return http.build();
	}
	
	@Bean
	PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
//	@Autowired
//	public void authenticate(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication()
//			.withUser("manager")
//			.password("{noop}abcd")
//			.roles("MANAGER");
//		auth.inMemoryAuthentication()
//			.withUser("admin")
//			.password("{noop}abcd")
//			.roles("ADMIN");
//	}
	
//	@Autowired
//	private DataSource dataSource;
//	
//	@Autowired
//	public void authenticate(AuthenticationManagerBuilder auth) throws Exception {
//		auth.jdbcAuthentication()
//			.dataSource(dataSource)
//			.usersByUsernameQuery("select username, concat('{noop}', password) password, "
//									+ "enable from member where username=?")
//			.authoritiesByUsernameQuery("select username, role from member where username=?");
//	}
}

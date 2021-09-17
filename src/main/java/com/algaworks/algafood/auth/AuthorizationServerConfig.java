package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
/**
 * Classe de configuração do AuthorizationServer
 * 
 * access_token: tempo padrão de validade: 12h
 * refresh_token: tempo padrão de validade: 30d
 * 
 * @author Leonardo
 *
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private UserDetailsService userDetailService;
	
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		//Configuração do clientes autorizados a acessar este Authorization Server
		clients
			.inMemory()
				.withClient("algafood-web") //Nome do cliente
				.secret(passwordEncoder.encode("web123")) //Chave senha do cliente
				.authorizedGrantTypes("password","refresh_token") //Usando o fluxo Password Credentials
				.scopes("write", "read")
				.accessTokenValiditySeconds(6 * 60 * 60) // 6h padrão é 12h
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60d padrão é 30d
			.and()
				.withClient("app-mobile") //Nome do cliente
				.secret(passwordEncoder.encode("mob123")) //Chave senha do cliente
				.authorizedGrantTypes("password", "outro-grant-type") //Usando o fluxo Password Credentials
				.scopes("write", "read")
			.and()
				.withClient("api-check-token") //Nome da api que quer se autenticar no Authorization Server
				.secret(passwordEncoder.encode("api123")); //Secret da api
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		//Informa que para fazer a requisição de check_token é necessário estar autenticado
		security.checkTokenAccess("isAuthenticated()");
		//security.checkTokenAccess("permitAll()"); //Permite acesso sem estar autenticado 	
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authManager)
			.userDetailsService(userDetailService)
			.reuseRefreshTokens(false); //Reutilizar o refresh_token
	}
}

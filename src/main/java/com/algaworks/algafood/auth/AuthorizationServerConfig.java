package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
/**
 * Classe de configuração do AuthorizationServer
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
	
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		//Configuração do clientes autorizados a acessar este Authorization Server
		clients
			.inMemory()
				.withClient("algafood-web") //Nome do cliente
				.secret(passwordEncoder.encode("web123")) //Chave senha do cliente
				.authorizedGrantTypes("password") //Usando o fluxo Password Credentials
				.scopes("write", "read")
				.accessTokenValiditySeconds(60 * 60 * 6) // 6h. padrão é 12h
			.and()
				.withClient("app-mobile") //Nome do cliente
				.secret(passwordEncoder.encode("mob123")) //Chave senha do cliente
				.authorizedGrantTypes("password", "outrogranttype") //Usando o fluxo Password Credentials
				.scopes("write", "read");
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authManager);
	}
}

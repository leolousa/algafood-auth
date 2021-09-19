package com.algaworks.algafood.auth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
/**
 * Classe de configuração do Authorization Server
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
				// Endereço para gerar Code Verifier e Code Challenge: https://tonyxu-io.github.io/pkce-generator/
				// URL para o Authorization Server: http://auth.algafood.local:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://aplicacao-cliente
			    // URL para o Authorization Server com PCSE SHA256:
			    // http://auth.algafood.local:8081/oauth/authorize?response_type=code&client_id=foodanalytics&redirect_uri=http://foodanalytics.local:8082$code_challenge&code_challenge_method=s256
				.withClient("foodanalytics")
				.secret(passwordEncoder.encode("food123"))
				.authorizedGrantTypes("authorization_code") //Usando o fluxo Authorization Code Grant Type
				.scopes("write","read")
				.redirectUris("http://foodanalytics.local:8082") //URL de retorno do Authorization Server para a app cliente
				
			.and()
				.withClient("api-check-token") //Nome da api(Resource Server) que quer se autenticar no Authorization Server
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
			.reuseRefreshTokens(false) //Reutilizar o refresh_token
			.accessTokenConverter(jwtAccessTokenConverter()) // Utiliza nosso métod para gerar Tokens JWT Transparent
			.tokenGranter(tokenGranter(endpoints)); 
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
		
		jwtAccessTokenConverter.setSigningKey("algafood");
		
		return jwtAccessTokenConverter;
	}
	
	// Método que instancia o Autorization Code com PKCE
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
}

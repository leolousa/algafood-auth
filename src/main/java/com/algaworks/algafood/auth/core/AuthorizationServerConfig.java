package com.algaworks.algafood.auth.core;

import java.util.Arrays;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
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
	private DataSource dataSource;
	
	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private UserDetailsService userDetailService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		//Configuração do clientes em Banco de dados, autorizados a acessar este Authorization Server
		clients.jdbc(dataSource);
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		//Informa que para fazer a requisição de check_token é necessário estar autenticado
		//security.checkTokenAccess("isAuthenticated()");
		security.checkTokenAccess("permitAll()") //Permite acesso sem estar autenticado
			.tokenKeyAccess("permitAll()"); //Para acessar o endpoint da chave pública
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		
		var enhancerChain = new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(
				Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokenConverter()));
		
		endpoints
			.authenticationManager(authManager)
			.userDetailsService(userDetailService)
			.reuseRefreshTokens(false) //Reutilizar o refresh_token
			.accessTokenConverter(jwtAccessTokenConverter()) // Utiliza nosso métod para gerar Tokens JWT Transparent
			.tokenEnhancer(enhancerChain)
			.approvalStore(approvalStore(endpoints.getTokenStore())) // Para retornar a aprovação granular do scope
			.tokenGranter(tokenGranter(endpoints)); 
	}
	
	private ApprovalStore approvalStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		
		return approvalStore;
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
	    var jwtAccessTokenConverter = new JwtAccessTokenConverter();
	    
	    var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
	    var keyStorePass = jwtKeyStoreProperties.getPassword();
	    var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
	    
	    var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
	    var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
	    
	    jwtAccessTokenConverter.setKeyPair(keyPair);
	    
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

package com.algaworks.algafood.auth.core;

import java.util.HashMap;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

/**
 * Classe para adição de novas propriedades
 * no Transparent Token antes de ele ser emitido
 * 
 * @author Leonardo
 *
 */
public class JwtCustomClaimsTokenEnhancer implements TokenEnhancer {

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		
		if (authentication.getPrincipal() instanceof AuthUser) { 
			//Verificação para saber se é um AuthUser (Authentication Code)
			var authUser = (AuthUser) authentication.getPrincipal(); 
			
			var info = new HashMap<String, Object>();
			info.put("nome_completo", authUser.getFullName());
			info.put("usuario_id", authUser.getUserId());
			
			var oAuth2AccesToken = (DefaultOAuth2AccessToken) accessToken;
			oAuth2AccesToken.setAdditionalInformation(info);
		}
		
		return accessToken;
	}

}

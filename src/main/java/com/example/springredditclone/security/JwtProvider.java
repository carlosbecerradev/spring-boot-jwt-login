package com.example.springredditclone.security;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.annotation.PostConstruct;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.example.springredditclone.exceptions.SpringRedditException;
import org.springframework.security.core.userdetails.User;

import io.jsonwebtoken.Jwts;

@Service
public class JwtProvider {
	
	private KeyStore keyStore;
	
	@PostConstruct
	public void init() {
		try {
			keyStore = KeyStore.getInstance("JKS");
			InputStream resourceAsStream = getClass().getResourceAsStream("/springblog.jks");
			keyStore.load(resourceAsStream, "key12345".toCharArray());
		} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
			throw new SpringRedditException("Exception ocurred while loading keystore");
		}
	}
	
	public String generateToken(Authentication authentication) {
		User principal = (User)authentication.getPrincipal();
		return Jwts.builder()
				.setSubject(principal.getUsername())
				.signWith(getPrivateKey())
				.compact();
	}

	private PrivateKey getPrivateKey() {
		try {
			return (PrivateKey) keyStore.getKey("springblog", "key12345".toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
			throw new SpringRedditException("Exception ocurred while retrieving public key from keystore");
		}
	}
}

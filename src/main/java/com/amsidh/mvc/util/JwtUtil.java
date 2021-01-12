package com.amsidh.mvc.util;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.amsidh.mvc.model.LoginRequestModel;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {

	private String secret = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private String expireTimeInMillSec = "300000";

	public String generateToken(LoginRequestModel loginRequestModel) {

		Date now = new Date();
		Map<String, Object> claims = new HashMap<>();
		claims.put("alg", "HS256");
		claims.put("typ", "JWT");

		return Jwts.builder().setHeaderParams(claims).setSubject(loginRequestModel.getUsername())
				.signWith(SignatureAlgorithm.HS256, Base64.getEncoder().encodeToString(secret.getBytes()))
				.setIssuedAt(now).setExpiration(new Date(now.getTime() + Long.parseLong(expireTimeInMillSec)))
				.compact();
	}

	public Claims getClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(Base64.getEncoder().encodeToString(secret.getBytes())).parseClaimsJws(token)
				.getBody();
	}

	public String getUsernameFromToken(String token) {
		return getClaimsFromToken(token).getSubject();
	}

	public Date getExpirationDate(String token) {
		return getClaimsFromToken(token).getExpiration();
	}

	public Boolean isTokenExpired(String token) {
		return getExpirationDate(token).before(new Date());
	}

	public Boolean isTokenValidated(String token) {
		return !isTokenExpired(token);
	}

}


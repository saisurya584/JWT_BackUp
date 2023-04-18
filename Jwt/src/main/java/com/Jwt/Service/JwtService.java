package com.Jwt.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;


import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {

    String sceret="5970337336763979244226452948404D635166546A576D5A7134743777217A25";

    public String generateToken(String userName) {
        Map<String,Object> claims=new HashMap<>();
        return createToken(userName,claims);
    }

    private String createToken(String userName, Map<String,Object> claims) {
      return Jwts.builder()
              .setClaims(claims)
              .setSubject(userName)
              .setIssuedAt(new Date(System.currentTimeMillis()))
              .setExpiration(new Date(System.currentTimeMillis()+1000*60*60))
              .signWith(getSignKey(),SignatureAlgorithm.HS256).compact();
    }

    private Key getSignKey() {
        byte []keysBytes= Decoders.BASE64.decode(sceret);
        return Keys.hmacShaKeyFor(keysBytes);
    }

    public String exactUser(String token)
    {
        return exactClaims(token,Claims::getSubject);
    }

    private <T>T exactClaims(String token, Function<Claims,T> reslove) {

        final Claims claims=exactAllClaims(token);
        return reslove.apply(claims);

    }

    private Claims exactAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Date exactExpirate(String token)
    {
        return exactClaims(token,Claims::getExpiration);
    }

    public Boolean isExpirate(String token)
    {
        return exactExpirate(token).before(new Date());
    }

    public Boolean vaildate(String token, UserDetails userDetails){
        final String userName=exactUser(token);
        return (userName.equals(userDetails.getUsername())&&!isExpirate(token));
    }

}

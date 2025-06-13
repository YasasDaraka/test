package lk.ijse.gdse66.helloshoes.service.impl;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import lk.ijse.gdse66.helloshoes.entity.User;
import lk.ijse.gdse66.helloshoes.repository.UserRepo;
import lk.ijse.gdse66.helloshoes.service.JwtService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Service
public class JwtServiceImpl implements JwtService {

    @Value("${token.key}")
    String jwtKey;
    @Autowired
    UserRepo userRepo;
    @Autowired
    ModelMapper mapper;
    @Override
    public String extractUserName(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("role",userDetails.getAuthorities());
        Date currentDate = new Date();
        Date expiredDate = new Date(currentDate.getTime() + 10000 * 600);
        String accessToken = Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(currentDate)
                .setExpiration(expiredDate)
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();

        return accessToken;
    }

    @Override
    public String generateRefreshToken(String username) {
        User user = userRepo.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("user not found"));
        long refreshTokenExpirationInMs = 7 * 24 * 60 * 60 * 1000;
        return Jwts.builder()
                .setSubject(username)
                .claim("email", user.getEmail())
                .claim("role", user.getRole())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpirationInMs))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(getSignKey()).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        String subject = extractClaims(token, Claims::getSubject);
        return subject.equals(userDetails.getUsername()) && !isExpired(token);
    }

    private Key getSignKey(){
        byte[] bytes = Decoders.BASE64.decode(jwtKey);
        return Keys.hmacShaKeyFor(bytes);
    }

    private Claims getAllClaims(String token){
        return Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
    }

    private <T> T extractClaims(String token, Function<Claims,T> claimResolve){
        Claims claims = getAllClaims(token);
        return claimResolve.apply(claims);
    }

    @Override
    public Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(getSignKey())
                .parseClaimsJws(token)
                .getBody();
    }
    private boolean isExpired(String token){
        Date expiredDate = extractClaims(token, Claims::getExpiration);
        return expiredDate.before(new Date());
    }


}

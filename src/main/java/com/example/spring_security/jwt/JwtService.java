package com.example.spring_security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    @Value("${security.jwt.secret-key}")
    private String secreatKey;

    @Value("${custom.jwt.expiration-time}")
    private Long jwtExpiration;

    
    /**
     * Extracts the username from the provided JWT token.
     *
     * @param token the JWT token from which the username is to be extracted
     * @return the username (subject) contained in the token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts a specific claim from the provided JWT token using the given claims resolver function.
     *
     * @param <T>           The type of the claim to be extracted.
     * @param token         The JWT token from which the claim is to be extracted.
     * @param claimsResolver A function that defines how to extract the desired claim from the Claims object.
     * @return The extracted claim of type T.
     * @throws io.jsonwebtoken.JwtException If the token is invalid or cannot be parsed.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Generates a JWT token for the given user details.
     *
     * @param userDetails the user details for which the token is to be generated
     * @return a JWT token as a String
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generates a JWT token with the specified extra claims and user details.
     *
     * @param extraClaims  A map containing additional claims to include in the token.
     * @param userDetails  The user details object containing information about the user.
     * @return A string representing the generated JWT token.
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Retrieves the expiration time for the JWT (JSON Web Token).
     *
     * @return the expiration time in milliseconds.
     */
    public long getExpirationTime() {
        return jwtExpiration;
    }

    /**
     * Builds a JWT token with the specified claims, user details, and expiration time.
     *
     * @param extraClaims A map of additional claims to include in the token.
     * @param userDetails The user details containing the username to be set as the subject of the token.
     * @param expiration  The expiration time in milliseconds from the current time.
     * @return A signed and compacted JWT token as a String.
     */
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey())
                .compact();
    }

    /**
     * Checks if the provided JWT token has expired.
     *
     * @param token the JWT token to be checked
     * @return {@code true} if the token has expired, {@code false} otherwise
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Validates the provided JWT token by checking if the username extracted from the token
     * matches the username of the given user details and ensures that the token is not expired.
     *
     * @param token the JWT token to validate
     * @param userDetails the user details containing the username to compare against
     * @return {@code true} if the token is valid and not expired, {@code false} otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Extracts the expiration date from the provided JWT token.
     *
     * @param token the JWT token from which the expiration date is to be extracted
     * @return the expiration date of the token
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Retrieves the signing key used for generating and validating JWTs.
     * The key is decoded from a Base64-encoded secret key and used to create
     * an HMAC-SHA key.
     *
     * @return the signing key as a {@link java.security.Key} object.
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secreatKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

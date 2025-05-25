package com.example.spring_security.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.example.spring_security.user.repository.UserRepository;

@Configuration
public class SecurityConfiguration {
 private final UserRepository userRepository;

    public SecurityConfiguration(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    UserDetailsService userDetailsService() {
        return email -> userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures and provides an {@link AuthenticationManager} bean.
     * 
     * @param config the {@link AuthenticationConfiguration} used to retrieve the
     *               {@link AuthenticationManager}.
     * @return the configured {@link AuthenticationManager} instance.
     * @throws Exception if an error occurs while retrieving the {@link AuthenticationManager}.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Configures and provides an {@link AuthenticationProvider} bean.
     * <p>
     * This method sets up a {@link DaoAuthenticationProvider} with a custom
     * {@link org.springframework.security.core.userdetails.UserDetailsService}
     * and a password encoder. The {@link DaoAuthenticationProvider} is responsible
     * for authenticating users based on the provided user details and password.
     * </p>
     *
     * @return an instance of {@link AuthenticationProvider} configured with
     *         a user details service and password encoder.
     */
    @Bean
    AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

}

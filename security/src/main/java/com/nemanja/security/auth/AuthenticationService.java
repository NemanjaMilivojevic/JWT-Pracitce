package com.nemanja.security.auth;

import com.nemanja.security.config.JwtService;
import com.nemanja.security.user.Role;
import com.nemanja.security.user.User;
import com.nemanja.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequset requset) {
        var user = User.builder()
                .firstname(requset.getFirstname())
                .lastname(requset.getLastname())
                .email(requset.getEmail())
                .password(passwordEncoder.encode(requset.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder()
            .token(jwtToken)
            .build();
    }

    public AuthenticationResponse authentitcate(AuthenticationRequset requset) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(requset.getEmail(),requset.getPassword()));
        var user = userRepository.findByEmail(requset.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}

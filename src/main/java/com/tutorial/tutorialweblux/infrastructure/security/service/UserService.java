package com.tutorial.tutorialweblux.infrastructure.security.service;

import com.tutorial.tutorialweblux.infrastructure.exception.CustomException;
import com.tutorial.tutorialweblux.infrastructure.security.entity.User;
import com.tutorial.tutorialweblux.infrastructure.security.enums.Role;
import com.tutorial.tutorialweblux.infrastructure.security.jwt.JwtProvider;
import com.tutorial.tutorialweblux.infrastructure.security.dto.CreateUserDto;
import com.tutorial.tutorialweblux.infrastructure.security.dto.LoginDto;
import com.tutorial.tutorialweblux.infrastructure.security.dto.TokenDto;
import com.tutorial.tutorialweblux.infrastructure.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final JwtProvider jwtProvider;

    private final PasswordEncoder passwordEncoder;

    public Mono<TokenDto> login(LoginDto dto) {
        return userRepository.findByUsernameOrEmail(dto.getUsername(), dto.getUsername())
                .filter(user -> passwordEncoder.matches(dto.getPassword(), user.getPassword()))
                .map(user -> new TokenDto(jwtProvider.generateToken(user)))
                .switchIfEmpty(Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "bad credentials")));
    }

    public Mono< User > create( CreateUserDto dto) {
        User user = User.builder()
                .username(dto.getUsername())
                .email(dto.getEmail())
                .password(passwordEncoder.encode(dto.getPassword()))
                .roles( Role.ROLE_USER.name())
                .build();
        Mono<Boolean> userExists = userRepository.findByUsernameOrEmail(user.getUsername(), user.getEmail()).hasElement();
        return userExists
                .flatMap(exists -> exists ?
                        Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "username or email already in use"))
                        : userRepository.save(user));
    }
}

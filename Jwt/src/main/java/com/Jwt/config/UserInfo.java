package com.Jwt.config;

import com.Jwt.entity.User;
import com.Jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.Optional;
@Component
public class UserInfo implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        Optional<User> byUserName = userRepository.findByUserName(userName);
        return byUserName.map(UserInfoImp::new).orElseThrow(
                ()->new UsernameNotFoundException("user not found"+userName)
        );
    }
}

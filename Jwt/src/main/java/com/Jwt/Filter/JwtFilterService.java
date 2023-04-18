package com.Jwt.Filter;

import com.Jwt.Service.JwtService;
import com.Jwt.config.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Component
public class JwtFilterService extends OncePerRequestFilter {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserInfo userInfo;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
      String AuthHeader=request.getHeader("Authorization");
      String Token=null;
      String userName=null;

      if(AuthHeader!=null && AuthHeader.startsWith("Bearer "))
      {
          Token=AuthHeader.substring(7);
          userName=jwtService.exactUser(Token);
      }
      if(userName!=null && SecurityContextHolder.getContext().getAuthentication()==null)
      {
          UserDetails userDetails = userInfo.loadUserByUsername(userName);
          if(jwtService.vaildate(Token,userDetails))
          {
              UsernamePasswordAuthenticationToken token=new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
              token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
              SecurityContextHolder.getContext().setAuthentication(token);
          }
      }
      filterChain.doFilter(request,response);
    }
}

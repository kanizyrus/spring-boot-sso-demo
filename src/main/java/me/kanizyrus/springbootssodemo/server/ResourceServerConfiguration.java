package me.kanizyrus.springbootssodemo.server;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
  @Override
  public void configure(HttpSecurity http) throws Exception {
    /*
     * Protect the "/me" path with the access token by declaring that our app is a Resource Server
     */
    http
      .antMatcher("/me")
      .authorizeRequests().anyRequest().authenticated();
  }
}
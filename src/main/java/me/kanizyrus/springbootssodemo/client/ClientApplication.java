package me.kanizyrus.springbootssodemo.client;
/*
 * The ClientApplication class MUST NOT be created in the same package (or a sub-package) of the SocialApplication class.
 * Otherwise, Spring will load some ClientApplication auto-configurations while starting the SocialApplication server,
 * resulting in startup errors.
 */

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@EnableAutoConfiguration
@Configuration
@EnableOAuth2Sso
@RestController
public class ClientApplication {

    @RequestMapping("/")
    public String home(Principal user) {
        return "Hello " + user.getName();
    }

    public static void main(String[] args) {
        /* Explicit name for a configuration file */
        new SpringApplicationBuilder(ClientApplication.class)
                .properties("spring.config.name=client").run(args);
    }

}
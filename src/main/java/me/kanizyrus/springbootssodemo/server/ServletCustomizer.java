package me.kanizyrus.springbootssodemo.server;

import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.web.servlet.ErrorPage;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

@Configuration
public class ServletCustomizer {
    /* Register a mapping of errors messages and pages, especially 401 from external SSO servers. */
    @Bean
    public EmbeddedServletContainerCustomizer customizer() {
        return container -> {
            container.addErrorPages(new ErrorPage(HttpStatus.UNAUTHORIZED, "/unauthenticated"));
        };
    }
}

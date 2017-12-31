package me.kanizyrus.springbootssodemo.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@SpringBootApplication
/* Enable SSO but with more manual setup as a business client */
@EnableOAuth2Client
/* Enable auth mechanism to issue access token of ourselves */
@EnableAuthorizationServer
/* Use Controller (not a @RestController) so it can handle the redirect. */
@Controller
@ComponentScan(basePackages = "me.kanizyrus.springbootssodemo.server")
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class SpringBootSsoDemoApplication extends WebSecurityConfigurerAdapter {

    private static final String AUTHORIZED_ORG = "spring-projects";

	@Autowired
	private OAuth2ClientContext oauth2ClientContext;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/**")                                                       //All requests are protected by default
                .authorizeRequests()
                .antMatchers("/", "/login**", "/webjars/**").permitAll() //The home page and login endpoints are explicitly excluded
                .anyRequest().authenticated()                                        //All other endpoints require an authenticated user
            .and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")) //Unauthenticated users are re-directed to the home page
			.and()
			    .logout()
				.logoutSuccessUrl("/")
				.permitAll()
			.and()
			    .csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			.and()
				.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
	}

    /* Use a composite filter that can handle more than one authentication path */
    private Filter ssoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilter(facebook(), "/login/facebook"));
        filters.add(ssoFilter(github(), "/login/github"));
        filter.setFilters(filters);
        return filter;
    }

    private Filter ssoFilter(ClientResources client, String path) {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
        filter.setRestTemplate(template);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(
                client.getResource().getUserInfoUri(), client.getClient().getClientId());
        tokenServices.setRestTemplate(template);
        filter.setTokenServices(tokenServices);
        return filter;
    }

    @Bean
    @ConfigurationProperties("github")
    public ClientResources github() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("facebook")
    public ClientResources facebook() {
        return new ClientResources();
    }

    /**
     * Handling the Redirects
     * The last change we need to make is to explicitly support the redirects from our app to Facebook.
     * This is handled in Spring OAuth2 with a servlet Filter, and the filter is already available in the application
     * context because we used @EnableOAuth2Client. All that is needed is to wire the filter up so that it gets called
     * in the right order in our Spring Boot application. To do that we need a FilterRegistrationBean as follows.
     * @param filter
     * @return
     */
    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(
            OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    /**
     * Verify if the user logging in with github belongs to the selected organization.
     * Spring Boot has provided an easy extension point: if we declare a @Bean of type AuthoritiesExtractor it will be
     * used to construct the authorities (typically "roles") of an authenticated user
     */
    /*
    @Bean
    public AuthoritiesExtractor authoritiesExtractor(OAuth2RestOperations template) {
        return map -> {
            String url = (String) map.get("organizations_url");
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> orgs = template.getForObject(url, List.class);
            if (orgs.stream()
                    .anyMatch(org -> AUTHORIZED_ORG.equals(org.get("login")))) {
                return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER");
            }
            throw new BadCredentialsException("Not in the selected origanization");
        };
    }
    */

    /**
     * Inject OAuth2RestOperations as a bean.
     */
//    @Bean
//    public OAuth2RestTemplate oauth2RestTemplate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
//        return new OAuth2RestTemplate(resource, context);
//    }

    /* A bad practice to expose everything to browser client */
	@RequestMapping("/userbadpractice")
	public @ResponseBody Principal userBadPractice(Principal principal) {
		return principal;
	}

	/* Converted the Principal into a Map so as to hide the parts that we don’t want to expose to the browser */
    @RequestMapping({ "/user", "/me" })
    /* Add @ResponseBody to prevent circular view generation. */
    public @ResponseBody Map<String, String> user(Authentication authentication) {
        Map<String, String> map = new LinkedHashMap<>();
        // User name is returned from external auth servers instead of real names.
        map.put("name", authentication.getName());
        return map;
    }

    /* To support the flag setting in the client we need to be able to capture an authentication error and redirect to the home page with that flag set in query parameters. */
    @RequestMapping("/unauthenticated")
    public String unauthenticated() {
        return "redirect:/?error=true";
    }

	public static void main(String[] args) {
		SpringApplication.run(SpringBootSsoDemoApplication.class, args);
	}

    private class ClientResources {

        /*
         *  the wrapper uses @NestedConfigurationProperty to instructs the annotation processor to crawl that type for
         *  meta-data as well since it does not represents a single value but a complete nested type.
         */
        @NestedConfigurationProperty
        private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

        @NestedConfigurationProperty
        private ResourceServerProperties resource = new ResourceServerProperties();

        public AuthorizationCodeResourceDetails getClient() {
            return client;
        }

        public ResourceServerProperties getResource() {
            return resource;
        }
    }
}

package in.ashishkumar.moneymanager.security;

import in.ashishkumar.moneymanager.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // -----------------------------------------
        // ✅ 1. BYPASS JWT FOR PUBLIC ROUTES
        // -----------------------------------------
        String path = request.getServletPath();

        if (path.startsWith("/api/v1.0/login")
                || path.startsWith("/api/v1.0/register")
                || path.startsWith("/api/v1.0/activate")) {

            filterChain.doFilter(request, response);
            return;
        }

        // -----------------------------------------
        // ✅ 2. Extract JWT Token from header
        // -----------------------------------------
        final String authHeader = request.getHeader("Authorization");
        String email = null;
        String jwt = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);

            try {
                email = jwtUtil.extractUsername(jwt);
            } catch (Exception e) {
                // Invalid token, continue without authentication
                filterChain.doFilter(request, response);
                return;
            }
        }

        // -----------------------------------------
        // ✅ 3. Validate and set authentication
        // -----------------------------------------
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            if (jwtUtil.validateToken(jwt, userDetails)) {

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // -----------------------------------------
        // Continue filter chain
        // -----------------------------------------
        filterChain.doFilter(request, response);
    }
}

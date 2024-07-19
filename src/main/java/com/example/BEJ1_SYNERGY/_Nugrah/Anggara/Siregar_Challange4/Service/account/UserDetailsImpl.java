package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.account;

import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.account.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


@Setter
@Getter
public class UserDetailsImpl implements UserDetails {

    private String email;
    private String password;
    private List<GrantedAuthority> authorites;

    public UserDetailsImpl(String email, String password, List<GrantedAuthority> authorites) {
        this.email = email;
        this.password = password;
        this.authorites = authorites;
    }

    public UserDetailsImpl(String username, List<GrantedAuthority> authorities) {
        this.email = username;
        this.authorites = authorities;
    }

    public static UserDetailsImpl build(OidcUser oidcUser) {
        List<GrantedAuthority> authorities = oidcUser.getAuthorities().stream()
                .map(authority -> (GrantedAuthority) authority)
                .collect(Collectors.toList());
        return new UserDetailsImpl(oidcUser.getEmail(), authorities);
    }

    public static UserDetails build(User user) {
        List<GrantedAuthority> authorities = user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        return new UserDetailsImpl(user.getUsername(),user.getPassword(),authorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorites;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

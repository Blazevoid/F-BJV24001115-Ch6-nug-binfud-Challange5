package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.account;

import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Order;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.Accessors;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;


@Entity
@Setter
@Getter
@Accessors(chain = true)
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    private String username;
    private String email_address;
    private String password;

    private boolean active = Boolean.FALSE;

    private String otp;
    private LocalDate expiredTime;

    @OneToMany(mappedBy = "user",cascade = CascadeType.ALL)
    private List<Order> orders;


    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles",
    joinColumns = @JoinColumn(name = "user_id"),
    inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public User(String username, String email, Set<Role> roles) {
        this.username = username;
        this.email_address = email;
        this.roles = roles;
    }
}


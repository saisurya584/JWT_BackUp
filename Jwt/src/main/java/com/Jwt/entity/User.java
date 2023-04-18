package com.Jwt.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import javax.persistence.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="userdetails",uniqueConstraints = {@UniqueConstraint(columnNames = {"userName"})})
public class User {
    private String userName;
    private String password;
    private String name;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String roles;
}

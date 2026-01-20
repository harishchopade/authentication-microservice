package com.smartkhata.authentication.enums;

public enum Role {
    USER,
    ADMIN;

    public String withPrefix() {
        return "ROLE_" + this.name();
    }
}

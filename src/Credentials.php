<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication;

class Credentials
{
    private $memberId;
    private $role;
    private $refreshToken;

    public function __construct(
        string $memberId,
        string $username,
        string $role,
        ?string $refreshToken = null
    ) {
        $this->memberId = $memberId;
        $this->username = $username;
        $this->role = $role;
        $this->refreshToken = $refreshToken;
    }

    public function memberId() : string
    {
        return $this->memberId;
    }

    public function username() : string
    {
        return $this->username;
    }

    public function role() : string
    {
        return $this->role;
    }

    public function refreshToken() : ?string
    {
        return $this->refreshToken;
    }

    public function withRole($role) : self
    {
        $credentials = clone $this;
        $credentials->role = $role;

        return $credentials;
    }
}

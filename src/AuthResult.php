<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication;

/**
 * Value object containing result
 */
class AuthResult
{
    private $success;
    private $member;
    private $reason;
    private $refreshToken;
    private $role;

    public function __construct(
        bool $success,
        ?MemberAdapter\HasMemberAttributes $member = null,
        ?string $role = null,
        ?AuthFailReason $reason = null,
        ?string $refreshToken = null
    ) {
        $this->success          = $success;
        $this->member           = $member;
        $this->role             = $role;
        $this->reason           = $reason;
        $this->refreshToken     = $refreshToken;
    }

    public function success() : bool
    {
        return $this->success;
    }

    public function reason() : ?AuthFailReason
    {
        return $this->reason;
    }

    public function role() : ?string
    {
        return $this->role;
    }

    public function member() : ?MemberAdapter\HasMemberAttributes
    {
        return $this->member;
    }

    public function refreshToken() : ?string
    {
        return $this->refreshToken;
    }
}

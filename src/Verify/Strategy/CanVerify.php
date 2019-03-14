<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Verify\Strategy;
use Mauricek\PsrAuthentication\MemberAdapter\HasMemberAttributes;

interface CanVerify {
    public function generateToken() : string;
    public function send(HasMemberAttributes $member, string $token) : void;
    public function expiresAfter() : int;
}

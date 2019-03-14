<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\MemberAdapter;

interface CanCreateMember
{
    public function createMember(
        string $id,
        string $registrationIp,
        string $email,
        string $username,
        string $passwordHash
    ) : void;
}

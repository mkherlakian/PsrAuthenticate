<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\RoleCalculator;

use Mauricek\PsrAuthentication\MemberAdapter\HasMemberAttributes;

interface RoleCalculator
{
    public function calculateRole(
        HasMemberAttributes $member,
        ?string $currentRole = null,
        string $browserFingerprint = null
    );
}

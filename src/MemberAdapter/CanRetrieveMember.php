<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\MemberAdapter;

interface CanRetrieveMember
{
    public function retrieveMemberById(string $id) : ?HasMemberAttributes;
    public function retrieveMemberByUsernameOrEmail(string $usernameOrEmail) : ?HasMemberAttributes;
}

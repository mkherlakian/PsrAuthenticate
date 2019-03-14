<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\MemberAdapter;

/**
 * Interface that implementor can use to define a member.
 */
interface HasMemberAttributes
{
    public function id() : string;
    public function isActive() : bool;
    public function status() : string;
    public function username() : string;
    public function passwordHash() : string;
    public function email() : string;
    public function phoneNumber() : string;
    public function emailVerified() : bool;
    public function phoneVerified() : bool;
    public function twoFactorSeed() : ?string;
    public function role() : string;
}

<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\RoleCalculator;

use Mauricek\PsrAuthentication\MemberAdapter\HasMemberAttributes;

class DefaultRoleCalculator implements RoleCalculator
{
    public function calculateRole(
        HasMemberAttributes $member,
        ?string $currentRole = null,
        string $browserFingerprint = null //,
//        array $knownMemberFingerprints
    ) : string {
        if(is_null($currentRole) || $currentRole == 'anonymous')  {
            return 'auth_0';
        }

        if($currentRole ==  'auth_0') {
            if(!$member->emailVerified()) {
                return 'email_verification_challenge';
            }

            if(!is_null($member->twoFactorSeed())) {
                return 'login_challenge';
            }

            //Browser challenge


            return $member->role();
        }
    }
}

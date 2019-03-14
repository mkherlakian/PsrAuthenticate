<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication;

use MabeEnum\Enum;

class AuthFailReason extends Enum
{
    const MEMBER_NOT_EXISTS                         = 'member_not_exists';
    const MEMBER_NOT_ACTIVE                         = 'member_not_active';
    const MEMBER_NOT_ACTIVE_WAITING_VERIFICATION    = 'member_waiting_verification';
    const WRONG_PASSWORD                            = 'wrong_password';
    const VERIFICATION_FAILED_SIGNATURE             = 'verification_failed_signature';
    const VERIFICATION_FAILED_DATA                  = 'verification_failed_data_error';
    const VERIFICATION_FAILED_EXPIRED               = 'verification_failed_expired';
    const VERIFICATION_FAILED_JTI                   = 'verification_failed_jti';
    const INVALID_REFRESH_TOKEN                     = 'invalid_refresh_token';
    const REFRESH_TOKEN_EXPIRED                     = 'refresh_token_expired';
}

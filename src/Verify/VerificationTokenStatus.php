<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Verify;

use MabeEnum\Enum;

class VerificationTokenStatus extends Enum
{
    const VALID = 'valid';
    const INVALID = 'invalid';
    const CONSUMED = 'consumed';
}

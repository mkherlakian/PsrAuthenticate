<?php

namespace Mauricek\PsrAuthentication\Verify\Sender;

use Mauricek\PsrAuthentication\Verify\Email;
use Mauricek\PsrAuthentication\Verify\CanSend;

interface CanSendEmail extends CanSend
{
    public function send(Email $email, string $name);
}

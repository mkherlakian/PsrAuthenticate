<?php

namespace Mauricek\PsrAuthentication\Verify\Sender;

use Mauricek\PsrAuthentication\Verify\Email;
use Mauricek\PsrAuthentication\Verify\CanSend;

interface CanSendSms extends CanSend
{
    public function send(PhoneNumber $number, string $name);
}

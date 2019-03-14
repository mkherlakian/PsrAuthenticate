<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Strategy\Verify;

use Ramsey\Uuid\Uuid;
use Mauricek\PsrAuthentication\Verify\Sender\CanSendEmail;
use Mauricek\PsrAuthentication\Verify\Email;
use Mauricek\PsrAuthentication\MemberAdapter\HasMemberAttributes;

class Sms implements CanVerify
{
    private $smsSender;

    public function __construct(CanSendSms $sender)
    {
        $this->smsSender = $sender;
    }

    public function generateToken() : string
    {
        $token = rand(100001, 999998);
        return (string)$token;
    }

    public function send(HasMemberAttributes $member, string $token) : void
    {
        $phone = PhoneNumber::fromNumber($member->phoneNumber());
        $name = $member->username();

        $this->emailSender->send($phone, $username);
    }

    public function expiresAfter() : int
    {
        return 60;
    }
}

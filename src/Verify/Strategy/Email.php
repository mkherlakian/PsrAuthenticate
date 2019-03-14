<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Verify\Strategy;

use Ramsey\Uuid\Uuid;
use Mauricek\PsrAuthentication\Verify\Sender\CanSendEmail;
use Mauricek\PsrAuthentication\Verify\Email as EmailVO;
use Mauricek\PsrAuthentication\MemberAdapter\HasMemberAttributes;

class Email implements CanVerify
{
    public function __construct(CanSendEmail $sender)
    {
        $this->emailSender = $sender;
    }

    public function generateToken() : string
    {
        return (string)Uuid::uuid4();
    }

    public function send(HasMemberAttributes $member, string $token) : void
    {
        $email = EmailVO::fromAddress($member->email());
        $name = $member->username();

        $this->emailSender->send($email, $username);
    }

    public function expiresAfter() : int
    {
        return 60;
    }
}

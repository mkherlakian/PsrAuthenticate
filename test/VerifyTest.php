<?php

namespace MauricekTest\AuthenticateTest;

use PHPUnit\Framework\TestCase;
use Mauricek\PsrAuthentication\AuthStore\AuthStore;
use Mauricek\PsrAuthentication\Verify;
use Mauricek\PsrAuthentication\Verify\Strategy\PluginManager as VerifyPluginManager;
use Mauricek\PsrAuthentication\Verify\Strategy\Email as EmailStrategy;
use Mauricek\PsrAuthentication\Verify\Strategy\CanVerify;
use Mauricek\PsrAuthentication\Verify\Email;
use Mauricek\PsrAuthentication\Verify\Sender\CanSendEmail;
use Mauricek\PsrAuthentication\Verify\VerificationTokenStatus;
use Mauricek\PsrAuthentication\MemberAdapter\HasMemberAttributes;
use Mauricek\PsrAuthentication\Verify\Exception\InvalidTokenException;
use Prophecy\Argument;

class VerifyTest extends TestCase
{
    public function setUp()
    {
    }

    private function prepareVerify(AuthStore $authStore, CanVerify $strategy)
    {
        $verifyPM = $this->prophesize(VerifyPluginManager::class);
        $verifyPM->get(EmailStrategy::class)->willReturn($strategy);

        $verify = new Verify($authStore, $verifyPM->reveal());
        return $verify;
    }

    private function getMember() : HasMemberAttributes
    {
        $member = new class implements HasMemberAttributes {
            public function id() : string { return '56514659-0e4b-4fd1-858c-c307fa705b49'; }
            public function isActive() : bool { return true; }
            public function status() : string { return 'active'; }
            public function username() : string { return 'testuser'; }
            public function passwordHash() : string { return 'abcd1234'; }
            public function email() : string { return 'testemail@domain.com'; }
            public function phoneNumber() : string { return '+1-111-222-3333'; }
            public function emailVerified() : bool { return false; }
            public function phoneVerified() : bool { return false; }
            public function twoFactorSeed() : ?string { return 'seedvalue'; }
            public function role() : string {return 'member'; }
        };

        return $member;
    }

    private function getValidToken() : string
    {
        return 'ff0f9b3d-933a-464c-927c-35e58bc24188';
    }

    public function testInitiateVerification()
    {
        $expiresAfter = 60;

        $authStore = $this->prophesize(AuthStore::class);
        $authStore->storeVerificationToken(
            $this->getMember()->id(),
            EmailStrategy::class,
            $this->getValidToken(),
            (string)VerificationTokenStatus::VALID(),
            $expiresAfter
        );

        $strategy = $this->prophesize(EmailStrategy::class);
        $strategy->generateToken()->willReturn($this->getValidToken());
        $strategy->expiresAfter()->willReturn(60);
        $strategy->send($this->getMember(), $this->getValidToken())->shouldBeCalled();

        $verify = $this->prepareVerify($authStore->reveal(), $strategy->reveal());

        $verify->initiateVerification('email', $this->getMember());
    }

    public function testIsValidToken()
    {
        $expiresAfter = time() + 3600;

        $authStore = $this->prophesize(AuthStore::class);
        $authStore->fetchVerificationToken(
            $this->getMember()->id(),
            EmailStrategy::class,
            $this->getValidToken()
        )->willReturn([
            [
                'id' => '',
                'token' => $this->getValidToken(),
                'method' => EmailStrategy::class,
                'status' => VerificationTokenStatus::VALID()]
        ]);

        $strategy = $this->prophesize(EmailStrategy::class);

        $verify = $this->prepareVerify($authStore->reveal(), $strategy->reveal());

        $this->assertTrue($verify->isValidToken('email', $this->getMember()->id(), $this->getValidToken()));
    }

    public function testIsValidTokenTokenNotExists()
    {
        $expiresAfter = time() + 3600;

        $authStore = $this->prophesize(AuthStore::class);
        $authStore->fetchVerificationToken(
            $this->getMember()->id(),
            EmailStrategy::class,
            Argument::Any()
        )->willReturn([
        ]);

        $strategy = $this->prophesize(EmailStrategy::class);

        $verify = $this->prepareVerify($authStore->reveal(), $strategy->reveal());

        $this->assertFalse($verify->isValidToken('email', $this->getMember()->id(), 'an_invalid_token'));
    }

    public function testIsValidTokenTokenInvalidToken()
    {
        $expiresAfter = time() + 3600;

        $authStore = $this->prophesize(AuthStore::class);
        $authStore->fetchVerificationToken(
            $this->getMember()->id(),
            EmailStrategy::class,
            Argument::Any()
        )->willReturn([
            [
                'status' => (string)Verify\VerificationTokenStatus::CONSUMED()
            ]
        ]);

        $strategy = $this->prophesize(EmailStrategy::class);

        $verify = $this->prepareVerify($authStore->reveal(), $strategy->reveal());

        $this->assertFalse($verify->isValidToken('email', $this->getMember()->id(), 'an_invalid_token'));
    }

    public function testConsumeToken()
    {
        $authStore = $this->prophesize(AuthStore::class);

        $authStore->fetchVerificationToken(
            $this->getMember()->id(),
            EmailStrategy::class,
            $this->getValidToken()
        )->willReturn([
            [
                'id' => '',
                'token' => $this->getValidToken(),
                'method' => EmailStrategy::class,
                'status' => VerificationTokenStatus::VALID()]
        ]);

        $authStore->storeVerificationToken(
            $this->getMember()->id(),
            EmailStrategy::class,
            $this->getValidToken(),
            VerificationTokenStatus::CONSUMED()
        )->shouldBeCalledTimes(1);

        $strategy = $this->prophesize(EmailStrategy::class);

        $verify = $this->prepareVerify($authStore->reveal(), $strategy->reveal());

        $verify->consumeToken('email', $this->getMember()->id(), $this->getValidToken());
    }

    /**
     * @expectedException \Mauricek\PsrAuthentication\Verify\Exception\InvalidTokenException
     */
    public function testConsumeTokenInvalidToken()
    {
        $authStore = $this->prophesize(AuthStore::class);

        $authStore->fetchVerificationToken(
            $this->getMember()->id(),
            EmailStrategy::class,
            $this->getValidToken()
        )->willReturn([
        ]);

        $authStore->storeVerificationToken(
            $this->getMember()->id(),
            EmailStrategy::class,
            $this->getValidToken(),
            VerificationTokenStatus::CONSUMED()
        )->shouldNotBeCalled();

        $strategy = $this->prophesize(EmailStrategy::class);

        $verify = $this->prepareVerify($authStore->reveal(), $strategy->reveal());

        $verify->consumeToken('email', $this->getMember()->id(), $this->getValidToken());
    }
}

<?php

declare(strict_types=1);

namespace MauricekTest\Authenticate;

use PHPUnit\Framework\TestCase;
use Mauricek\PsrAuthentication\Authenticate;
use Mauricek\PsrAuthentication\CanHashPassword;
use Mauricek\PsrAuthentication\AuthFailReason;
use Mauricek\PsrAuthentication\MemberAdapter\CanRetrieveMember;
use Mauricek\PsrAuthentication\MemberAdapter\HasMemberAttributes;
use Mauricek\PsrAuthentication\JwtBuilderPluginManager;
use Mauricek\PsrAuthentication\AuthResult;
use Mauricek\PsrAuthentication\AuthStore\AuthStore;
use Ramsey\Uuid\Uuid;
use Assert\Assertion;
use Prophecy\Argument;

class AuthenticateTest extends TestCase
{
    public function setUp()
    {
        $hasher = $this->prophesize()->willImplement(CanHashPassword::class);
        $hasher->verify('correct_password', 'some_hash')->willReturn(true);
        $hasher->verify('wrong_password', 'some_hash')->willReturn(false);
        $this->hasher = $hasher;

        $activeUuid = Uuid::uuid4();
        $activeUuidNoToken = Uuid::uuid4();
        $inactiveUuid = Uuid::uuid4();
        $unverifiedUuid = Uuid::uuid4();

        $this->activeUuidNoToken = $activeUuidNoToken;
        $this->activeUuid = $activeUuid;

        $authStore = $this->prophesize();
        $authStore->willImplement(AuthStore::class);
    }

    public function testSuccessfulLogin()
    {
        $authStore = $this->prophesize();
        $authStore->willImplement(AuthStore::class);

        $authStore->fetchRefreshTokenById((string)$this->activeUuid)->willReturn([
            ['token' => (string)Uuid::uuid4()]
        ]);
        $authStore->createRefreshToken((string)$this->activeUuid, Argument::any(), 'auth_0')->shouldBeCalledTimes(0);
        $authStore->deleteExpiredTokens((string)$this->activeUuid)->shouldBeCalledTimes(1);

        $member = $this->prophesize(HasMemberAttributes::class);
        $member->isActive()->willReturn(true);
        $member->passwordHash()->willReturn('some_hash');
        $member->id()->willReturn($this->activeUuid);

        $memberRetriever = $this->prophesize()->willImplement(CanRetrieveMember::class);
        $memberRetriever->retrieveMemberByUsernameOrEmail('active@domain.com')->willReturn($member->reveal());

        $authenticate = new Authenticate(
            $memberRetriever->reveal(),
            $this->hasher->reveal(),
            $authStore->reveal()
        );

        $authResult = $authenticate->login(
            'active@domain.com',
            'correct_password'
        );

        $this->assertInstanceOf(AuthResult::class, $authResult);
        $this->assertEquals($this->activeUuid, $authResult->member()->id());
        $this->assertEquals(true, $authResult->success());
        $this->assertTrue(Assertion::uuid($authResult->refreshToken()));
    }

    /**
     * Same flow as login, ensure that createRefreshToken
     * is called
     */
    public function testSuccessfulLoginNoToken()
    {
        $authStore = $this->prophesize();
        $authStore->willImplement(AuthStore::class);

        $authStore->fetchRefreshTokenById((string)$this->activeUuidNoToken)->willReturn(null);
        $authStore->createRefreshToken((string)$this->activeUuidNoToken, Argument::any(), 'auth_0')->shouldBeCalledTimes(1);
        $authStore->deleteExpiredTokens((string)$this->activeUuidNoToken)->shouldBeCalled();

        $member = $this->prophesize(HasMemberAttributes::class);
        $member->isActive()->willReturn(true);
        $member->passwordHash()->willReturn('some_hash');
        $member->id()->willReturn($this->activeUuidNoToken);

        $memberRetriever = $this->prophesize()->willImplement(CanRetrieveMember::class);
        $memberRetriever->retrieveMemberByUsernameOrEmail('active_notoken@domain.com')->willReturn($member->reveal());

        $authenticate = new Authenticate(
            $memberRetriever->reveal(),
            $this->hasher->reveal(),
            $authStore->reveal()
        );

        $authResult = $authenticate->login(
            'active_notoken@domain.com',
            'correct_password'
        );

        $this->assertInstanceOf(AuthResult::class, $authResult);
        $this->assertEquals($this->activeUuidNoToken, $authResult->member()->id());
        $this->assertEquals(true, $authResult->success());
        $this->assertTrue(Assertion::uuid($authResult->refreshToken()));
    }

    public function testUnsuccessfulLoginMemberNotExists()
    {
        $authStore = $this->prophesize();
        $authStore->willImplement(AuthStore::class);

        $memberRetriever = $this->prophesize()->willImplement(CanRetrieveMember::class);
        $memberRetriever->retrieveMemberByUsernameOrEmail('inexistant@domain.com')->willReturn(null);

        $authenticate = new Authenticate(
            $memberRetriever->reveal(),
            $this->hasher->reveal(),
            $authStore->reveal()
        );

        $authResult = $authenticate->login(
            'inexistant@domain.com',
            'wtv_password'
        );

        $this->assertInstanceOf(AuthResult::class, $authResult);
        $this->assertTrue($authResult->reason()->is(AuthFailReason::MEMBER_NOT_EXISTS()));
    }

    public function testUnsuccessfulLoginMemberNotActive()
    {
        $authStore = $this->prophesize();
        $authStore->willImplement(AuthStore::class);

        $member = $this->prophesize(HasMemberAttributes::class);
        $member->isActive()->willReturn(false);
        $member->status()->willReturn('BANNED');
        $member->id()->willReturn($this->activeUuidNoToken);

        $memberRetriever = $this->prophesize()->willImplement(CanRetrieveMember::class);
        $memberRetriever->retrieveMemberByUsernameOrEmail('inactive@domain.com')->willReturn($member->reveal());

        $authenticate = new Authenticate(
            $memberRetriever->reveal(),
            $this->hasher->reveal(),
            $authStore->reveal()
        );

        $authResult = $authenticate->login(
            'inactive@domain.com',
            'wtv_password'
        );


        $this->assertInstanceOf(AuthResult::class, $authResult);
        $this->assertTrue($authResult->reason()->is(AuthFailReason::MEMBER_NOT_ACTIVE()));
    }

    public function testUnsuccessfulLoginMemberWrongPassword()
    {
        $authStore = $this->prophesize();
        $authStore->willImplement(AuthStore::class);

        $member = $this->prophesize(HasMemberAttributes::class);
        $member->isActive()->willReturn(true);
        $member->passwordHash()->willReturn('some_hash');
        $member->id()->willReturn($this->activeUuid);

        $memberRetriever = $this->prophesize()->willImplement(CanRetrieveMember::class);
        $memberRetriever->retrieveMemberByUsernameOrEmail('active@domain.com')->willReturn($member->reveal());

        $authenticate = new Authenticate(
            $memberRetriever->reveal(),
            $this->hasher->reveal(),
            $authStore->reveal()
        );

        $authResult = $authenticate->login(
            'active@domain.com',
            'wrong_password'
        );

        $this->assertInstanceOf(AuthResult::class, $authResult);
        $this->assertTrue($authResult->reason()->is(AuthFailReason::WRONG_PASSWORD()));
    }
}

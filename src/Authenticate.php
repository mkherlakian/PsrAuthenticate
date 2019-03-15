<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Parser;
use Ramsey\Uuid\Uuid;
use Assert\Assertion;
use DateTimeInterface;
use Mauricek\PsrAuthentication\MemberAdapter\HasMemberAttributes;

class Authenticate
{
    private const DEFAULT_ROLE_ON_LOGIN = 'auth_0';

    private $memberAdapter;
    private $passwordHasher;
    private $roleOnLogin;

    public function __construct(
        MemberAdapter\CanRetrieveMember $memberAdapter,
        CanHashPassword $passwordHasher,
        AuthStore\AuthStore $authStore
    ) {
        $this->memberAdapter    = $memberAdapter;
        $this->authStore        = $authStore;
        $this->passwordHasher   = $passwordHasher;
    }

    public function login(string $usernameOrEmail, string $password)
    {
        $member = $this
            ->memberAdapter
            ->retrieveMemberByUsernameOrEmail($usernameOrEmail);

        if(!$member)
        {
            return new AuthResult(false, null, null, AuthFailReason::MEMBER_NOT_EXISTS());
        }

        if(!$member->isActive())
        {
            if($member->status() == 'WAITING_VERIFICATION')
            {
                return new AuthResult(false, null, null, AuthFailReason::MEMBER_NOT_ACTIVE_WAITING_VERIFICATION());
            }

            return new AuthResult(false, $member, null, AuthFailReason::MEMBER_NOT_ACTIVE());
        }

        //Verify password
        if(!$this->passwordHasher->verify($password, $member->passwordHash()))
        {
            return new AuthResult(false, $member, null, AuthFailReason::WRONG_PASSWORD());
        }

        $role = $this->getRoleOnLogin(); //lowest possible role if no refresh token
                                         //There is a role calculator for this value but since it's an initial value,
                                         //that doesn't chnage, we set it to avoid injecting another dependency.

        //If we're here, the user is successfully authenticated -
        //if they already have a valid refresh token, pass it along with the JWT.
        //Otherwise create a new refresh token.
        $refreshToken = $this->loadOrGenerateRefreshToken($member, $role);

        return new AuthResult(
            true,
            $member,
            $role,
            null,
            $refreshToken
        );
    }

    protected function loadOrGenerateRefreshToken(HasMemberAttributes $member, string $role)
    {
        $this->authStore->deleteExpiredTokens($member->id());

        $tokenData = $this->authStore->fetchRefreshTokenById($member->id());

        if(empty($tokenData)) {
            $refreshToken = $this->generateRefreshToken();
            $this->authStore->createRefreshToken($member->id(), $refreshToken, $role);
        } else {
            $refreshToken = $tokenData[0]['token'];
        }

        return $refreshToken;
    }

    protected function generateRefreshToken()
    {
        return (string)Uuid::uuid4();
    }

    public function logout(string $id)
    {
        $this
            ->authStore
            ->invalidateActiveTokens($id);

        return new AuthResult(
            true
        );
    }

    public function refresh(string $refreshToken)
    {
        $tokenData = $this->authStore->fetchRefreshTokenByToken($refreshToken, true);

        if(empty($tokenData)) {
            return new AuthResult(false, null, null, AuthFailReason::INVALID_REFRESH_TOKEN());
        }

        $tokenData = $tokenData[0];
        if($tokenData['is_expired'] !== '0')
        {
            return new AuthResult(false, null, null, AuthFailReason::REFRESH_TOKEN_EXPIRED());
        }

        //Token is valid - issue new jwt
        $member = $this
            ->memberAdapter
            ->retrieveMemberById($tokenData['id']);

        return new AuthResult(
            true,
            $member,
            $tokenData['role'],
            null
        );

    }

    public function blacklistToken(TokenJti $jti, TokenExp $exp) : void
    {
        Assertion::uuid($jti->jti());

        $this->authStore->blacklistToken($jti->jti(), $exp->exp());
    }

    public function setRoleOnLogin(string $roleOnLogin)
    {
        $this->roleOnLogin = $roleOnLogin;
    }

    public function getRoleOnLogin()
    {
        if(is_null($this->roleOnLogin)) {
            $this->roleOnLogin = self::DEFAULT_ROLE_ON_LOGIN;
        }

        return $this->roleOnLogin;
    }
}

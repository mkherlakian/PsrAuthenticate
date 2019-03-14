<?php

namespace Mauricek\PsrAuthentication;

use Mauricek\PsrAuthentication\Verify\Strategy\PluginManager as VerifyPluginManager;
use Mauricek\PsrAuthentication\AuthStore\AuthStore;
use Mauricek\PsrAuthentication\MemberAdapter\HasMemberAttributes;
use Mauricek\PsrAuthentication\Verify\Exception;
use Assert\Assertion;

class Verify
{
    protected $verificationStrategy;
    protected $authStore;

    public function __construct(
        AuthStore $store,
        VerifyPluginManager $verifyPM
    ) {
        $this->authStore = $store;
        $this->verifyPM = $verifyPM;
    }

    public function initiateVerification(string $method, HasMemberAttributes $member) : void
    {
        $methodName = $this->methodtoClass($method);

        $verificationStrategy = $this->verifyPM->get($methodName);

        $token = $verificationStrategy->generateToken();

        $this->authStore->storeVerificationToken(
            $member->id(),
            $methodName,
            $token,
            Verify\VerificationTokenStatus::VALID(),
            $verificationStrategy->expiresAfter()
        );

        $verificationStrategy->send($member, $token);
    }

    public function isValidToken(string $method, string $memberId, string $token) : bool
    {
        $methodName = $this->methodtoClass($method);

        $records = $this->authStore->fetchVerificationToken($memberId, $methodName, $token);

        if(!$records || count($records) == 0) {
            return false;
        }

        return $records[0]['status'] == (string)Verify\VerificationTokenStatus::VALID();
    }

    public function consumeToken(string $method, string $memberId, string $token) : void
    {
        $methodName = $this->methodtoClass($method);

        if(!$this->isValidToken($method, $memberId, $token)) {
            throw new Exception\InvalidTokenException("Token is not valid");
        }

        $this->authStore->storeVerificationToken(
            $memberId,
            $methodName,
            $token,
            (string)Verify\VerificationTokenStatus::CONSUMED()
        );
    }

    private function methodtoClass($method)
    {
        $methodName = __NAMESPACE__.'\\Verify\\Strategy\\'.ucfirst($method);
        Assertion::classExists($methodName);

        return $methodName;
    }
}

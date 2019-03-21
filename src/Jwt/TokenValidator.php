<?php

use Mauricek\PsrAuthentication\AuthStore\AuthStore;
use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\TokenJti;
use Mauricek\PsrAuthentication\TokenExp;
use Mauricek\PsrAuthentication\Exception\InvalidArgumentException;
use Mauricek\PsrAuthentication\Exception\RuntimeException;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Assert\Assertion;

class JwtTokenValidator
{
    protected $tokenParser;
    protected $tokenSigner;
    protected $tokenValidator;
    protected $jwtParams;
    protected $authStore;

    public function  __construct(
        AuthStore $authStore,
        Parser $tokenParser,
        Signer $tokenSigner,
        ValidationData $tokenValidator,
        array $jwtParams
    ) {
        Assertion::keyExists($jwtParams, 'iss');
        Assertion::keyExists($jwtParams, 'aud');
        Assertion::keyExists($jwtParams, 'signing_key');

        $this->authStore        = $authStore;
        $this->tokenParser      = $tokenParser;
        $this->tokenSigner      = $tokenSigner;
        $this->tokenValidator   = $tokenValidator;
        $this->jwtParams        = $jwtParams;
    }

    public function validate(string $token) : Credentials
    {
        $authResult = $this->validateJwt($jwt);
        if(!$authResult) {
            throw new RuntimeException('Unauthorized - '.(string)$authResult->reason());
        }

        $jwtParsed = $this->tokenParser->parse($jwt);

        $credentials = new Credentials(
            $jwtParsed->getClaim('sub'),
            $jwtParsed->getClaim('user'),
            $jwtParsed->getClaim('role')
        );

        return $credentials;
    }

    protected function validateJwt(string $tokenString, ?DateTimeInterface $now = null) : bool
    {
        $token = $this->tokenParser->parse($tokenString);

        $this->tokenValidator->setIssuer($this->jwtParams['iss']);
        $this->tokenValidator->setAudience($this->jwtParams['aud']);

        try {
            $signatureTest = $token->verify($this->tokenSigner, $this->jwtParams['signing_key']);
        } catch(\BadMethodCallException $e) {
            $this->throwUnauthorizedRequest('verification_failed_signature');
        }

        if(!$signatureTest) {
            $this->throwUnauthorizedRequest('verification_failed_signature');
        }

        //expired?
        if($token->isExpired($now)) {
            $this->throwUnauthorizedRequest('verification_failed_expired');
        }

        $tokenDataTest = $token->validate($this->tokenValidator);
        if(!$tokenDataTest) {
            $this->throwUnauthorizedRequest('verification_failed_data');
        }

        //Blacklisted?
        if($this->authStore->isTokenBlacklisted($token->getClaim('jti'))) {
            $this->throwUnauthorizedRequest('verification_failed_jti');
        }

        return true;
    }

    protected function throwUnauthorizedRequest(string $reason)
    {
        throw new RuntimeException('Unauthorized - '.$reason);
    }
}

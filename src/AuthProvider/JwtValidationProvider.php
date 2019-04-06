<?php

namespace Mauricek\PsrAuthentication\AuthProvider;

use PHPUnit\Framework\TestCase;
use Mauricek\PsrAuthentication\AuthStore\AuthStore;
use Mauricek\PsrAuthentication\AuthProvider\JwtValidationProvider;
use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\TokenJti;
use Mauricek\PsrAuthentication\TokenExp;
use Mauricek\PsrAuthentication\Exception\RuntimeException;
use Mauricek\PsrAuthentication\Exception\InvalidArgumentException;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zend\Diactoros\Response\JsonResponse;
use Prophecy\Argument;
use Assert\Assertion;

class JwtValidationProvider implements AuthValidationProvider
{
    protected $tokenParser;
    protected $tokenSigner;
    protected $tokenValidator;
    protected $jwtParams;
    protected $authStore;
    protected $jti;
    protected $exp;

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

    public function validate(ServerRequestInterface $request) : ?Credentials
    {
        $authorizationHeader = $request->getHeader('Authorization');
        if(empty($authorizationHeader[0]))
        {
            return null;
        }

        list($jwt) = sscanf($authorizationHeader[0], 'Bearer %s');
        if(!$jwt) {
            return null;
        }

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

        $this->jti = new TokenJti($jwtParsed->getClaim('jti'));
        $this->exp = new TokenExp($jwtParsed->getClaim('exp'));

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

    public function additionalParameters() : array
    {
        return [
            TokenJti::class => $this->jti,
            TokenExp::class => $this->exp,
        ];
    }

    protected function throwUnauthorizedRequest(string $reason)
    {
        throw new RuntimeException('Unauthorized - '.$reason);
    }
}

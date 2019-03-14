<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Middleware;

use Mauricek\PsrAuthentication\AuthStore\AuthStore;
use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\TokenJti;
use Mauricek\PsrAuthentication\TokenExp;
use Mauricek\PsrAuthentication\Exception\InvalidArgumentException;
use Mauricek\PsrAuthentication\Exception\RuntimeException;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zend\Diactoros\Response\HtmlResponse;
use Zend\Diactoros\Response\EmptyResponse;
use Zend\Expressive\Router\RouteResult;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Assert\Assertion;

class ValidateTokenMiddleware implements MiddlewareInterface
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

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $delegate
    ) : ResponseInterface {
        /**
         * Here we check if a token exists, and if it is valid.
         */
        $authorizationHeader = $request->getHeader('Authorization');
        if(empty($authorizationHeader[0]))
        {
            throw new InvalidArgumentException('Invalid request - missing Authoorization header');
        }

        list($jwt) = sscanf($authorizationHeader[0], 'Bearer %s');
        if(!$jwt) {
            throw new InvalidArgumentException('Invalid request - missing token');
        }

        //We found a jwt token in the auth bearer header
        $authResult = $this->validate($jwt);
        if(!$authResult) {
            throw new RuntimeException('Unauthorized - '.(string)$authResult->reason());
        }

        $jwtParsed = $this->tokenParser->parse($jwt);

        $credentials = new Credentials(
            $jwtParsed->getClaim('sub'),
            $jwtParsed->getClaim('user'),
            $jwtParsed->getClaim('role')
        );

        $jti = new TokenJti($jwtParsed->getClaim('jti'));
        $exp = new TokenExp($jwtParsed->getClaim('exp'));

        $request = $request
            ->withAttribute(Credentials::class, $credentials)
            ->withAttribute(TokenJti::class, $jti)
            ->withAttribute(TokenExp::class, $exp);

        $response = $delegate->handle($request);

        return $response;
    }

    protected function throwUnauthorizedRequest(string $reason)
    {
        throw new RuntimeException('Unauthorized - '.$reason);
    }

    protected function validate(string $tokenString, ?DateTimeInterface $now = null) : bool
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
}

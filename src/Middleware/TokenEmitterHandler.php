<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Middleware;

use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\JsonResponse;
use Mauricek\PsrAuthentication\AuthResult;
use Mauricek\PsrAuthentication\JwtBuilderPluginManager;
use Mauricek\PsrAuthentication\Credentials;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Parser;
use Assert\Assertion;
use Ramsey\Uuid\Uuid;

class TokenEmitterHandler
    implements RequestHandlerInterface
{
    private $tokenBuilderPluginManager;
    private $tokenParser;
    private $tokenSigner;
    private $tokenValidator;
    private $jwtParams;

    public function __construct(
        JwtBuilderPluginManager $jwtTokenBuilder,
        Parser $parser,
        Signer $jwtTokenSigner,
        ValidationData $jwtValidator,
        array $jwtParams
    ) {
        Assertion::keyExists($jwtParams, 'expiration');
        Assertion::keyExists($jwtParams, 'iss');
        Assertion::keyExists($jwtParams, 'aud');
        Assertion::keyExists($jwtParams, 'signing_key');
        Assertion::keyExists($jwtParams, 'refresh_expiration');

        $this->tokenBuilderPM   = $jwtTokenBuilder;
        $this->tokenSigner      = $jwtTokenSigner;
        $this->tokenValidator   = $jwtValidator;
        $this->tokenParser      = $parser;
        $this->jwtParams        = $jwtParams;
    }

    public function handle(ServerRequestInterface $request) : ResponseInterface
    {
        $credentials   = $request->getAttribute(Credentials::class);

        if(is_null($credentials))  {
            throw new Problems\ServerError(
                sprintf("No %s found in request", Credentials::class),
                'missing_credentials'
            );
        }

        $member     = $credentials->memberId();
        $role       = $credentials->role();
        $user       = $credentials->username();
        $refresh    = $credentials->refreshToken();

        $token = $this->tokenBuilderPM->get(Builder::class)
            ->setIssuer($this->jwtParams['iss'])
            ->setAudience($this->jwtParams['aud'])
            ->setIssuedAt(time())
            ->setExpiration(time() + $this->jwtParams['expiration'])
            ->setId(Uuid::uuid4())
            ->set('sub', $member)
            ->set('user', $user)
            ->set('role', $role)
            ->sign($this->tokenSigner, $this->jwtParams['signing_key'])
            ->getToken();

        $response['token'] = (string)$token;

        if($refresh) {
            $response['refresh_token'] = $credentials->refreshToken();
        }

        return new JsonResponse($response);
    }
}

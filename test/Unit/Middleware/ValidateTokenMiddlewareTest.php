<?php

use PHPUnit\Framework\TestCase;
use Mauricek\PsrAuthentication\AuthStore\AuthStore;
use Mauricek\PsrAuthentication\Middleware\ValidateTokenMiddleware;
use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\TokenJti;
use Mauricek\PsrAuthentication\TokenExp;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zend\Diactoros\Response\JsonResponse;
use Prophecy\Argument;

class ValidateTokenMiddlewareTest extends TestCase
{
    private $jwtKey;
    private $expiration;

    public function setUp()
    {
        $this->jwtKey = 'testkey';

        $authStore = $this->prophesize()->willImplement(AuthStore::class);
        $authStore->isTokenBlacklisted('abcd1234')->willReturn(false);

        $this->parser = new Parser();
        $this->signer = new Sha256();
        $this->validator = new ValidationData();

        $this->validator->setIssuer('http://mauricek.net/');
        $this->validator->setAudience('http://mauricek.net/');
        $this->validator->setId('abcd1234');

        $this->validateTokenMw = new ValidateTokenMiddleware(
            $authStore->reveal(),
            $this->parser,
            $this->signer,
            $this->validator,
            [
                'signing_key' => $this->jwtKey,
                'iss' => 'http://mauricek.net/',
                'aud' => 'http://mauricek.net/',
            ]
        );
    }

    private function generateToken($now = null, $jwtKey = null, $issuer = null)
    {
        $now = $now ?? time();
        $jwtKey = $jwtKey ?? $this->jwtKey;
        $issuer = $issuer ?? 'http://mauricek.net/';

        return (new Builder())
            ->setIssuer($issuer)
            ->setAudience('http://mauricek.net/') // Configures the audience (aud claim)
            ->setId('abcd1234', true) // Configures the id (jti claim), replicating as a header item
            ->setIssuedAt($now) // Configures the time that the token was issued (iat claim)
            ->setExpiration($now + 3600) // Configures the expiration time of the token (exp claim)
            ->set('sub', 'some_user_id')
            ->set('user', 'some_username')
            ->set('role', 'member')
            ->sign($this->signer, $jwtKey) //Sign
            ->getToken(); // Retrieves the generated token
    }

    public function testValidToken()
    {
//        $credentials = new Credentials('some_user_id', 'member');

        $now = time();

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getHeader('Authorization')->willReturn(["Bearer {$this->generateToken($now)}"]);
        $request
            ->withAttribute(
                Credentials::class,
                Argument::That(function($arg) {
                    return
                        $arg instanceOf Credentials &&
                        $arg->memberId() == 'some_user_id' &&
                        $arg->username() == 'some_username' &&
                        $arg->role() == 'member';
                })
            )
            ->willReturn($request);

        $request->withAttribute(
            TokenJti::class,
            Argument::That(function($arg){
                return $arg instanceOf TokenJti &&
                    $arg->jti() == 'abcd1234';
            })
        )
        ->willReturn($request);

        $request->withAttribute(
            TokenExp::class,
            Argument::That(function($arg) use ($now) {
                return $arg instanceOf TokenExp &&
                    $arg->exp() == $now + 3600;
            })
        )
        ->willReturn($request);

        $delegate = $this->prophesize(RequestHandlerInterface::class);
        $delegate->handle(Argument::Any())->willReturn(new JsonResponse(['success' => true]));

        $response = $this->validateTokenMw->process($request->reveal(), $delegate->reveal());
        $decoded = json_decode($response->getBody(), true);

        $this->assertEquals(['success' => true], $decoded);
    }

    /**
     * @expectedException \Mauricek\PsrAuthentication\Exception\InvalidArgumentException
     */
    public function testMissingHeader()
    {
        $request = $this->prophesize(ServerRequestInterface::class);
        $delegate = $this->prophesize(RequestHandlerInterface::class);

        $response = $this->validateTokenMw->process($request->reveal(), $delegate->reveal());
    }

    /**
     * @expectedException \Mauricek\PsrAuthentication\Exception\RuntimeException
     */
    public function testInvalidSignature()
    {
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getHeader('Authorization')->willReturn(["Bearer {$this->generateToken(null, 'invalid_key')}"]);

        $delegate = $this->prophesize(RequestHandlerInterface::class);

        $response = $this->validateTokenMw->process($request->reveal(), $delegate->reveal());
    }

    /**
     * @expectedException \Mauricek\PsrAuthentication\Exception\RuntimeException
     */
    public function testExpiredToken()
    {
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getHeader('Authorization')->willReturn(["Bearer {$this->generateToken(time() - 86400)}"]);

        $delegate = $this->prophesize(RequestHandlerInterface::class);

        $response = $this->validateTokenMw->process($request->reveal(), $delegate->reveal());
    }

    /**
     * @expectedException \Mauricek\PsrAuthentication\Exception\RuntimeException
     */
    public function testInvalidData()
    {
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getHeader('Authorization')->willReturn(["Bearer {$this->generateToken(null, null, 'fake_issuer')}"]);

        $delegate = $this->prophesize(RequestHandlerInterface::class);

        $response = $this->validateTokenMw->process($request->reveal(), $delegate->reveal());
    }

    /**
     * @expectedException \Mauricek\PsrAuthentication\Exception\RuntimeException
     */
    public function testBlacklistedToken()
    {
        $authStore = $this->prophesize()->willImplement(AuthStore::class);
        $authStore->isTokenBlacklisted('abcd1234')->willReturn(true);

        $this->validateTokenMw = new ValidateTokenMiddleware(
            $authStore->reveal(),
            $this->parser,
            $this->signer,
            $this->validator,
            [
                'signing_key' => $this->jwtKey,
                'iss' => 'http://mauricek.net/',
                'aud' => 'http://mauricek.net/',
            ]
        );

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getHeader('Authorization')->willReturn(["Bearer {$this->generateToken()}"]);

        $delegate = $this->prophesize(RequestHandlerInterface::class);

        $response = $this->validateTokenMw->process($request->reveal(), $delegate->reveal());
    }
}

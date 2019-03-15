<?php

use PHPUnit\Framework\TestCase;
use Mauricek\PsrAuthentication\AuthStore\AuthStore;
use Mauricek\PsrAuthentication\Middleware\TokenEmitterHandler;
use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\JwtBuilderPluginManager;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zend\Diactoros\Response\JsonResponse;
use Prophecy\Argument;

class TokenEmitterHandlerTest extends TestCase
{
    private $jwtKey;
    private $parser;
    private $signer;
    private $validator;
    private $tokenEmitterHandler;
    private $jwtPluginManager;

    public function setUp()
    {
        $this->jwtKey = 'testkey';

        $this->jwtPluginManager = $this
            ->prophesize(JwtBuilderPluginManager::class);
        $this
            ->jwtPluginManager
            ->get(Builder::class)
            ->willReturn(new Builder());

        $this->parser = new Parser();
        $this->signer = new Sha256();
        $this->validator = new ValidationData();

        $this->validator->setIssuer('http://mauricek.net/');
        $this->validator->setAudience('http://mauricek.net/');

        $this->tokenEmitterHandler = new TokenEmitterHandler(
            $this->jwtPluginManager->reveal(),
            $this->parser,
            $this->signer,
            $this->validator,
            [
                'signing_key' => $this->jwtKey,
                'iss' => 'http://mauricek.net/',
                'aud' => 'http://mauricek.net/',
                'expiration' => 60 * 5,
                'refresh_expiration' => 60*60*4,
            ]
        );
    }

    private function credentials($withRefresh = false)
    {
        return new Credentials(
            'some_user_id',
            'some_username',
            'member',
            $withRefresh ? 'some_refresh_token' : null
        );
    }

    public function testEmitTokenNoRefresh()
    {
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(Credentials::class)->willReturn($this->credentials());

        $response = $this->tokenEmitterHandler->handle($request->reveal());
        $decoded = json_decode($response->getBody(), true);

        $this->assertArrayHasKey('token', $decoded);
        $token = $decoded['token'];

        //parse
        $parsed = $this->parser->parse($token);

        //verify
        $this->assertTrue($parsed->verify($this->signer, $this->jwtKey));

        //validate
        $this->assertTrue($parsed->validate($this->validator));

        //Check custom claims
        $this->assertEquals($parsed->getClaim('sub'), 'some_user_id');
        $this->assertEquals($parsed->getClaim('user'), 'some_username');
        $this->assertEquals($parsed->getClaim('role'), 'member');
    }

    public function testEmitTokenWithRefresh()
    {
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(Credentials::class)->willReturn($this->credentials(true));

        $response = $this->tokenEmitterHandler->handle($request->reveal());
        $decoded = json_decode($response->getBody(), true);

        $this->assertArrayHasKey('refresh_token', $decoded);

        $refreshToken = $decoded['refresh_token'];
        $this->assertEquals('some_refresh_token', $refreshToken);
    }
}
